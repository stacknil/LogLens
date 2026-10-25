"""Local sanitizer campaign runner with retained commands, exits and raw logs."""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=pathlib.Path, required=True)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--seed', type=int, default=129130)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 900:
        parser.error('seconds must be 1..900 per target')
    source = pathlib.Path(__file__).resolve().parents[1]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    manifest_path = evidence / 'execution.json'
    if manifest_path.exists():
        parser.error('use a new evidence directory; existing runs are immutable')
    build = evidence / 'build'
    records = []
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    def run(label, command, timeout):
        start = time.monotonic()
        with (evidence / (label + '.log')).open('wb') as log:
            try:
                result = subprocess.run([str(x) for x in command], stdout=log, stderr=subprocess.STDOUT,
                                        env=env, timeout=timeout, cwd=source)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 'TIMEOUT'
        records.append({'label': label, 'command': [str(x) for x in command], 'exit': code,
                        'seconds': time.monotonic() - start,
                        'ASAN_OPTIONS': env['ASAN_OPTIONS'], 'UBSAN_OPTIONS': env['UBSAN_OPTIONS']})
        manifest_path.write_text(json.dumps(records, indent=2) + '\n')
        print(label, code, flush=True)
        if code != 0:
            raise SystemExit(1)
    run('configure', ['cmake', '-S', source, '-B', build, '-G', 'Ninja',
        '-DCMAKE_CXX_COMPILER=clang++', '-DCMAKE_BUILD_TYPE=RelWithDebInfo',
        '-DLOGLENS_WARNINGS_AS_ERRORS=ON', '-DLOGLENS_BUILD_FUZZERS=ON',
        '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer',
        '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'], 120)
    run('build', ['cmake', '--build', build, '-j2'], 600)
    run('ctest', ['ctest', '--test-dir', build, '--output-on-failure'], 180)
    corpus = evidence / 'corpus'
    run('generate', [sys.executable, source / 'scripts/generate-adversarial-corpus.py', '--output', corpus], 30)
    for target, folder, max_len in [('fuzz_parser', 'parser', 4096), ('fuzz_timestamp_day', 'timestamp_day', 32), ('fuzz_pipeline', 'pipeline', 97)]:
        existing = source / 'tests/fuzz/corpus' / folder
        if existing.is_dir():
            for seed in existing.iterdir():
                if seed.is_file():
                    shutil.copyfile(seed, corpus / folder / ('existing-' + seed.name))
        artifacts = evidence / 'failures' / folder
        artifacts.mkdir(parents=True, exist_ok=True)
        run(target, [build / target, corpus / folder, f'-seed={args.seed}',
            f'-max_total_time={args.seconds}', f'-max_len={max_len}', '-timeout=3',
            '-rss_limit_mb=1024', '-print_final_stats=1',
            '-artifact_prefix=' + str(artifacts) + os.sep], args.seconds + 60)


if __name__ == '__main__':
    main()
