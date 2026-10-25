#!/usr/bin/env python3
"""Matched local CLI observations; synthetic inputs, no historical timing claims."""
import argparse
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--lines', type=int, default=3000)
    workloads = ('dense', 'unsupported', 'long-fields', 'distinct-subjects', 'window-boundary', 'mixed')
    parser.add_argument('--workload', choices=workloads, help='rerun only the affected workload')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for workload in (args.workload,) if args.workload else workloads:
        rows = []
        for i in range(args.lines):
            seconds = (i % 2) * 600 if workload == 'window-boundary' else i % 600
            user = 'user-' + str(i % 7)
            # Keep the original 65,024-subject period, inside the documentation prefix.
            address = f'2001:db8::{i % (254 * 256) + 1:x}' if workload == 'distinct-subjects' else '203.0.113.1'
            program = 'sshd'
            message = f'Failed password for {user} from {address} port 50101 ssh2'
            if workload == 'unsupported' or (workload == 'mixed' and i % 3 == 0):
                message = 'unsupported synthetic message'
            if workload == 'long-fields':
                program = 'sudo'
                message = 'user-a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/echo ' + 'x' * 4096
            if workload == 'mixed' and i % 3 == 1:
                message = message.replace('Failed', 'Accepted')
            rows.append(f'Mar 10 09:{seconds // 60:02}:{seconds % 60:02} example-host {program}[4200]: {message}\n')
        source = args.output / (workload + '.log')
        source.write_text(''.join(rows), encoding='utf-8')
        for repeat in range(3):
            # Alternate execution order to reduce a systematic warm-cache advantage.
            builds = [('baseline', args.baseline), ('candidate', args.candidate)]
            if repeat % 2:
                builds.reverse()
            for label, binary in builds:
                target = args.output / f'{workload}-{repeat}-{label}'
                metrics = args.output / f'{workload}-{repeat}-{label}.time'
                command = ['/usr/bin/time', '-f', '%e %M', '-o', str(metrics), str(binary.resolve()),
                           '--mode', 'syslog', '--year', '2026', '--csv', str(source.resolve()), str(target.resolve())]
                started = time.monotonic()
                run = subprocess.run(command, capture_output=True, timeout=60)
                (args.output / f'{workload}-{repeat}-{label}.stderr').write_bytes(run.stderr)
                observation = dict(workload=workload, repeat=repeat, build=label, command=command,
                                   exit=run.returncode, wall_seconds=time.monotonic() - started,
                                   lines=args.lines, input_bytes=source.stat().st_size)
                if metrics.exists():
                    observation['time_elapsed_rss_kib'] = metrics.read_text().strip()
                results.append(observation)
                (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
                if run.returncode:
                    raise SystemExit(run.returncode)
        print(workload, 'complete', flush=True)


if __name__ == '__main__':
    main()
