"""Validate, sign and stage policy files; the workflow commits pairs atomically.

Edit policy/*.lst, never the signed root files. Serial numbers are assigned from
the verified published version. No private key is required for --check.
"""
import argparse
import base64
import ipaddress
import os
from pathlib import Path
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
NAMES = ('force-direct', 'force-tunnel', 'force-tunnel-cidr', 'blocked')
# Identical slots in Windows VerifiedRules.cs and Apple RulesUpdater.swift.
CLIENT_KEYS = (
    'at3grjFVOpGAydXmM5Z1xPsPDZtoPkfEL2PvVlYtjrA=',
    'dOidfEll74Z/2vmupX0tEUXjTWCksYPfVXBLkNgSorU=',
)
# All four existing published lists use this key. Rotation is a separate change.
SIGNING_PUBLIC_KEY = CLIENT_KEYS[1]
SERIAL = re.compile(r'^#\s*serial:\s*([0-9]+)\s*$', re.IGNORECASE)
MAX_SERIAL = 2**63 - 1


def validate(name, body):
    if len(body) > 256_000:
        raise ValueError(f'{name}: file exceeds client size limit')
    text = body.decode('utf-8')
    if not text.startswith(f'# {name}:'):
        raise ValueError(f'{name}: wrong policy purpose')
    lines = text.splitlines()
    serials = [(index, SERIAL.fullmatch(line)) for index, line in enumerate(lines)
               if re.match(r'^#\s*serial\s*:', line.strip(), re.IGNORECASE)]
    if (len(serials) != 1 or serials[0][0] >= 10 or not serials[0][1]
            or not 0 < int(serials[0][1][1]) <= MAX_SERIAL):
        raise ValueError(f'{name}: require one positive int64 serial in first 10 lines')
    entries = set()
    for line in lines:
        entry = line.split('#', 1)[0].strip()
        if not entry:
            continue
        if name.endswith('-cidr'):
            network = ipaddress.IPv4Network(entry, strict=True)
            if network.prefixlen == 0:
                raise ValueError(f'{name}: default route is not a policy subnet')
        else:
            labels = entry.split('.')
            if (len(entry) > 253 or len(labels) < 2 or entry != entry.lower()
                    or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)
                    or labels[-1].isdigit()):
                raise ValueError(f'{name}: invalid domain {entry!r}')
        if entry in entries:
            raise ValueError(f'{name}: duplicate entry {entry!r}')
        entries.add(entry)
    index, match = serials[0]
    return int(match[1]), index, lines


def verify_signature(name, body, encoded):
    signature = base64.b64decode(encoded.strip(), validate=True)
    if len(signature) != 64:
        raise ValueError(f'{name}: invalid signature size')
    for key in CLIENT_KEYS:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(signature, body)
            return
        except InvalidSignature:
            pass
    raise ValueError(f'{name}: signature rejected by both client keys')


def verify_published(root):
    published = {}
    for name in NAMES:
        body = (root / f'{name}.lst').read_bytes()
        validate(name, body)
        verify_signature(name, body, (root / f'{name}.lst.sig').read_bytes())
        published[name] = body
    return published


def prepare_changes(root):
    published = verify_published(root)
    changes = {}
    for name, body in published.items():
        serial, index, lines = validate(name, body)
        source = (root / 'policy' / f'{name}.lst').read_bytes()
        _, source_index, source_lines = validate(name, source)
        # The source serial is a placeholder; only the verified baseline counts.
        lines[index] = '# serial: AUTO'
        source_lines[source_index] = '# serial: AUTO'
        if lines == source_lines:
            continue
        if serial == MAX_SERIAL:
            raise ValueError(f'{name}: serial exhausted')
        source_lines[source_index] = f'# serial: {serial + 1}'
        candidate = ('\n'.join(source_lines) + '\n').encode('utf-8')
        validate(name, candidate)
        changes[name] = candidate
    return changes


def publish(root, key_pem):
    changes = prepare_changes(root)
    if not key_pem:
        raise ValueError('POLICY_SIGNING_KEY secret is missing; nothing published')
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError) as error:
        raise ValueError('POLICY_SIGNING_KEY must be the existing unencrypted Ed25519 PEM key') from error
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('POLICY_SIGNING_KEY is not Ed25519')
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode('ascii')
    if public != SIGNING_PUBLIC_KEY:
        raise ValueError('POLICY_SIGNING_KEY does not match the current publication key')
    # Validate every signature before writing any published file.
    signatures = {}
    for name, body in changes.items():
        encoded = base64.b64encode(key.sign(body)) + b'\n'
        verify_signature(name, body, encoded)
        signatures[name] = encoded
    for name, body in changes.items():
        (root / f'{name}.lst').write_bytes(body)
        (root / f'{name}.lst.sig').write_bytes(signatures[name])
    verify_published(root)
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check', action='store_true')
    modes.add_argument('--publish', action='store_true')
    modes.add_argument('--verify-published', action='store_true')
    args = parser.parse_args()
    try:
        if args.verify_published:
            verify_published(ROOT)
            print('All four published signatures accepted by client keys')
            return
        if args.publish:
            changes = publish(ROOT, os.environ.get('POLICY_SIGNING_KEY', '').encode('utf-8'))
        else:
            changes = prepare_changes(ROOT)
        for name, body in changes.items():
            print(f'{name}: serial {validate(name, body)[0]}')
        print(f'{len(changes)} policy file(s) ' + ('signed and verified' if args.publish else 'pending publication'))
    except (ValueError, OSError) as error:
        parser.exit(1, f'Policy publication refused: {error}\n')


if __name__ == '__main__':
    main()
