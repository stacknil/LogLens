"""Deterministic synthetic seeds. Never consumes real logs or contacts a service."""
import argparse
import json
import pathlib


def generate(root):
    entries = []
    def save(target, name, content, purpose):
        path = root / target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        entries.append({'path': path.relative_to(root).as_posix(), 'bytes': len(content),
                        'provenance': 'authored synthetic fixture', 'purpose': purpose})
    messages = [
        ('sshd', 'Failed password for user-a from 203.0.113.1 port 50101 ssh2'),
        ('sshd', 'Failed password for from from 203.0.113.1 port 50101 ssh2'),
        ('sshd', 'Failed password for illegal user user-a from 2001:db8::1 port 50101 ssh2'),
        ('sshd', 'Accepted keyboard-interactive/pam for user-a from 203.0.113.1 port 50101 ssh2'),
        ('sshd', 'Failed publickey for user-a from 203.0.113.1 port 50101 ssh2'),
        ('sshd', 'maximum authentication attempts exceeded for user-a from 203.0.113.1 port 50101 ssh2'),
        ('sshd', 'Failed password for user-a from 203.0.113.1. port 50101 ssh2'),
        ('sshd', 'Connection closed by 203.0.113.1 port 50101 [preauth]'),
        ('sudo', 'user-a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/echo from example'),
        ('sudo', 'user-a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/echo incorrect password attempt'),
        ('su', 'FAILED SU (to root) user-a on pts/0'),
        ('pam_unix(sshd:auth)', 'authentication failure; rhost=203.0.113.1 user=user-a'),
    ]
    for mode, prefix in [('syslog', 'Mar 10 09:00:00 '), ('journal', 'Tue 2026-03-10 17:00:00 +0800 ')]:
        for index, (program, message) in enumerate(messages):
            line = f'{prefix}example-host {program}[4200]: {message}'.encode()
            save('parser', f'{mode}-{index:02}', line, 'supported/unsupported/auth-field boundaries')
    seed = b'Mar 10 09:00:00 example-host sshd: Failed password for user-a from 203.0.113.1'
    for host in ('example-host', 'example.example'):
        for tag in ('sshd', 'sshd[0]', 'sshd[2147483647]', 'sshd[2147483648]'):
            save('parser', 'envelope-' + host + '-' + tag,
                 f'Mar 10 09:00:00 {host} {tag}: Failed password for user-a from 203.0.113.1 port 50101 ssh2'.encode(),
                 'hostname and PID presence/int boundary')
    for name, content in [('truncated', seed[:45]), ('nul', seed + b'\x00'), ('invalid-utf8', seed.replace(b'example-host', b'example-\xff'))]:
        save('parser', name, content, 'byte/truncation boundaries')
    for day in ('0', '1', '31', '32', '-255', '257', '2147483648'):
        save('timestamp_day', 'day-' + day.replace('-', 'negative-'), day.encode(), 'integer/day domain')
    for name, family, users in [('ssh-threshold', 0, [0] * 5), ('sudo-threshold', 11, [0] * 3), ('multi-user', 0, [0, 1, 2])]:
        seed = bytearray([0])
        for user in users:
            seed.extend([family, 0, user, 0])
        save('pipeline', name, bytes(seed), 'authored threshold witness; 4-byte records')
    seed = bytearray([1])
    for index in range(10):
        seed.extend([0, 0 if index < 5 else 11, 0, 0])
    save('pipeline', 'separated-episodes', bytes(seed), 'two five-event bursts separated by 1802 seconds')
    (root / 'manifest.json').write_text(json.dumps({'generator_version': 1, 'entries': entries}, indent=2) + '\n')
    print(f'{len(entries)} synthetic seeds written')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    generate(parser.parse_args().output)
