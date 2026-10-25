"""Independent UTF-8/JSON/CSV consumers and observation-corruption controls."""
import csv
import io
import json
import pathlib
import subprocess
import sys


def json_field(raw):
    # Preserve valid Unicode; represent each malformed UTF-8 byte as U+00XX.
    return ''.join(chr(ord(ch) - 0xDC00) if 0xDC80 <= ord(ch) <= 0xDCFF else ch
                   for ch in raw.decode('utf-8', errors='surrogateescape'))


def csv_field(raw):
    value = raw.decode('latin1')  # Byte-preserving CSV oracle, independent of UTF-8 policy.
    stripped = value.lstrip(' ')
    return "'" + value if stripped and stripped[0] in '=+-@\t\r\n' else value


def check_json(raw, expected):
    data = json.loads(raw.decode('utf-8'))
    assert data['findings'][0]['subject'] == expected
    assert data['findings'][0]['summary'] == expected
    assert data['findings'][0]['usernames'] == [expected]
    assert data['warnings'][0]['reason'] == expected
    assert {host['hostname'] for host in data['host_summaries']} == {expected, 'example-fixed-host'}
    assert sum(item['count'] for item in data['event_counts']) == data['parsed_event_count'] == 2
    for host in data['host_summaries']:
        assert sum(item['count'] for item in host['event_counts']) == host['parsed_event_count'] == 1


def check_csv(raw, expected):
    rows = list(csv.reader(io.StringIO(raw.decode('latin1'), newline=''), strict=True))
    assert len(rows) == 2 and len(rows[0]) == len(rows[1]) == 8
    assert rows[1][2] == rows[1][6] == rows[1][7] == expected


def detected(check, raw, expected):
    try:
        check(raw, expected)
    except (AssertionError, UnicodeError, ValueError, csv.Error, KeyError, IndexError):
        return True
    return False


def main():
    driver, output = sys.argv[1:3]
    extra = sys.argv[3:]
    if extra not in ([], ['--extended']):
        raise ValueError('only --extended is supported')
    root = pathlib.Path(output)
    subprocess.run([driver, str(root), *extra], check=True, timeout=120)
    failures = []
    controls = 0
    for entry in (root / 'fields.txt').read_text().splitlines():
        index, encoded = entry.split(' ')
        raw = bytes.fromhex(encoded)
        folder = root / index / 'first'
        expected_json, expected_csv = json_field(raw), csv_field(raw)
        content = (folder / 'report.json').read_bytes()
        csv_content = (folder / 'findings.csv').read_bytes()
        try:
            check_json(content, expected_json)
            check_csv(csv_content, expected_csv)
            warnings = list(csv.reader(io.StringIO((folder / 'warnings.csv').read_bytes().decode('latin1'), newline=''), strict=True))
            assert len(warnings) == 2 and len(warnings[1]) == 4 and warnings[1][3] == expected_csv
            for name in ('report.json', 'report.md', 'findings.csv', 'warnings.csv'):
                assert (folder / name).read_bytes() == (root / index / 'second' / name).read_bytes()
        except (AssertionError, UnicodeError, ValueError, csv.Error) as error:
            failures.append({'case': index, 'error': str(error) or type(error).__name__})
            continue
        # Controls corrupt the actual serialized artifacts consumed by the checker.
        assert detected(check_json, content[:-3], expected_json), 'JSON truncation control survived'
        changed = json.loads(content)
        changed['findings'][0]['subject'] = 'corrupted-observation'
        assert detected(check_json, json.dumps(changed).encode(), expected_json), 'JSON field control survived'
        assert detected(check_csv, csv_content + b'rogue,row\n', expected_csv), 'CSV row control survived'
        controls += 3
    result = {'failures': failures, 'negative_controls_detected': controls}
    (root / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
