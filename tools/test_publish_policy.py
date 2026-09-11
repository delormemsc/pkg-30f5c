import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import publish_policy as policy


class PublishedCompatibilityTests(unittest.TestCase):
    def test_real_published_files_are_accepted_by_client_keys(self):
        self.assertEqual(set(policy.verify_published(policy.ROOT)), set(policy.NAMES))

    def test_all_sources_are_valid_and_serials_will_increase(self):
        for name, body in policy.prepare_changes(policy.ROOT).items():
            previous = (policy.ROOT / f'{name}.lst').read_bytes()
            self.assertEqual(policy.validate(name, body)[0], policy.validate(name, previous)[0] + 1)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'policy').mkdir()
        # Ephemeral test fixture only; never used for real published files.
        self.key = Ed25519PrivateKey.generate()
        public = base64.b64encode(self.key.public_key().public_bytes_raw()).decode()
        self.patch = patch.multiple(policy, CLIENT_KEYS=(public,), SIGNING_PUBLIC_KEY=public)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.pem = self.key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
        for name in policy.NAMES:
            body = f'# {name}: fixture\n# serial: 7\n'.encode()
            if name.endswith('-cidr'):
                body += b'203.0.113.0/24\n'
            elif name != 'blocked':
                body += b'example.com\n'
            (self.root / 'policy' / f'{name}.lst').write_bytes(body)
            self.write_signed(name, body)

    def write_signed(self, name, body):
        (self.root / f'{name}.lst').write_bytes(body)
        (self.root / f'{name}.lst.sig').write_bytes(base64.b64encode(self.key.sign(body)) + b'\n')

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}

    def add_domain(self, name='force-tunnel', value=b'new.example\n'):
        path = self.root / 'policy' / f'{name}.lst'
        path.write_bytes(path.read_bytes() + value)

    def test_only_changed_pair_updates_and_next_run_is_idempotent(self):
        before = self.snapshot()
        self.add_domain()
        self.assertEqual(set(policy.publish(self.root, self.pem)), {'force-tunnel'})
        after = self.snapshot()
        self.assertEqual({name for name in before if before[name] != after[name]},
                         {'force-tunnel.lst', 'force-tunnel.lst.sig'})
        self.assertEqual(policy.validate('force-tunnel', after['force-tunnel.lst'])[0], 8)
        policy.verify_published(self.root)
        self.assertEqual(policy.publish(self.root, self.pem), {})
        self.assertEqual(after, self.snapshot())

    def test_serial_uses_latest_verified_publication_not_source_placeholder(self):
        name = 'force-tunnel'
        body = (self.root / f'{name}.lst').read_bytes().replace(b'serial: 7', b'serial: 21')
        self.write_signed(name, body)
        self.add_domain()
        policy.publish(self.root, self.pem)
        self.assertEqual(policy.validate(name, (self.root / f'{name}.lst').read_bytes())[0], 22)

    def test_no_change_does_not_bump_serial_for_line_endings(self):
        path = self.root / 'policy/force-tunnel.lst'
        path.write_bytes(path.read_bytes().replace(b'\n', b'\r\n'))
        self.assertEqual(policy.prepare_changes(self.root), {})

    def test_missing_key_fails_without_touching_published_files(self):
        self.add_domain()
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'secret is missing'):
            policy.publish(self.root, b'')
        self.assertEqual(before, self.snapshot())

    def test_wrong_key_fails_even_when_no_changes(self):
        wrong = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,
                                                         serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption())
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'current publication key'):
            policy.publish(self.root, wrong)
        self.assertEqual(before, self.snapshot())

    def test_corrupt_published_body_is_not_used_as_baseline(self):
        path = self.root / 'force-tunnel.lst'
        path.write_bytes(path.read_bytes() + b'tampered.example\n')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'signature rejected'):
            policy.publish(self.root, self.pem)
        self.assertEqual(before, self.snapshot())

    def test_crlf_conversion_of_published_bytes_is_rejected(self):
        path = self.root / 'force-tunnel.lst'
        path.write_bytes(path.read_bytes().replace(b'\n', b'\r\n'))
        with self.assertRaisesRegex(ValueError, 'signature rejected'):
            policy.verify_published(self.root)

    def test_swapped_published_pair_is_rejected_by_purpose(self):
        (self.root / 'force-tunnel.lst').write_bytes((self.root / 'force-direct.lst').read_bytes())
        (self.root / 'force-tunnel.lst.sig').write_bytes((self.root / 'force-direct.lst.sig').read_bytes())
        with self.assertRaisesRegex(ValueError, 'purpose'):
            policy.verify_published(self.root)

    def test_invalid_last_source_does_not_publish_earlier_valid_change(self):
        self.add_domain()
        self.add_domain('blocked', b'https://invalid.example/path\n')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'invalid domain'):
            policy.publish(self.root, self.pem)
        self.assertEqual(before, self.snapshot())

    def test_duplicates_are_rejected(self):
        self.add_domain(value=b'example.com\n')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            policy.prepare_changes(self.root)

    def test_bad_serial_headers_are_rejected(self):
        path = self.root / 'policy/force-tunnel.lst'
        original = path.read_bytes()
        for replacement in (b'# serial: -1', b'# serial: 0', b'# serial: 9223372036854775808',
                            b'# serial: 7\n#serial: 8', b'# serial: 7\n# serial: invalid',
                            b'# missing serial', b'\n' * 10 + b'# serial: 7'):
            with self.subTest(header=replacement):
                path.write_bytes(original.replace(b'# serial: 7', replacement))
                with self.assertRaisesRegex(ValueError, 'serial'):
                    policy.prepare_changes(self.root)

    def test_int64_serial_exhaustion_is_rejected(self):
        name = 'force-tunnel'
        body = (self.root / f'{name}.lst').read_bytes().replace(b'serial: 7', b'serial: 9223372036854775807')
        self.write_signed(name, body)
        self.add_domain()
        with self.assertRaisesRegex(ValueError, 'serial exhausted'):
            policy.prepare_changes(self.root)

    def test_default_and_invalid_cidrs_are_rejected(self):
        path = self.root / 'policy/force-tunnel-cidr.lst'
        original = path.read_bytes()
        for invalid in (b'0.0.0.0/0', b'203.0.113.1/24', b'::/0'):
            with self.subTest(entry=invalid):
                path.write_bytes(original + invalid + b'\n')
                with self.assertRaises(ValueError):
                    policy.prepare_changes(self.root)


if __name__ == '__main__':
    unittest.main()
