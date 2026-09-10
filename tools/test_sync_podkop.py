import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name('sync_podkop.py')
SHA = '1234567890abcdef1234567890abcdef12345678'
COMMIT = json.dumps({'sha': SHA, 'commit': {'committer': {
    'date': '2026-09-10T09:00:00Z'}}}).encode()
INSIDE = b'.ua\nexample.com\n'
OUTSIDE = b'gosuslugi.ru\nozon.ru\n'


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), 'mirror implementation is missing')
        spec = importlib.util.spec_from_file_location('sync_podkop', SCRIPT)
        self.sync = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.sync)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'Russia').mkdir()
        (self.root / 'Russia/inside-raw.lst').write_bytes(b'old.example\n')
        (self.root / 'Russia/outside-raw.lst').write_bytes(b'old.ru\n')
        (self.root / 'Russia/provenance.json').write_bytes(b'old provenance\n')
        (self.root / 'force-direct.lst').write_bytes(b'signed bytes\n')
        (self.root / 'force-direct.lst.sig').write_bytes(b'signature\n')

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes()
                for p in self.root.rglob('*') if p.is_file()}

    def fetcher(self, inside=INSIDE, outside=OUTSIDE):
        def fetch(url, max_bytes):
            if url == 'https://api.github.com/repos/itdoginfo/allow-domains/commits/main':
                return COMMIT
            prefix = f'https://raw.githubusercontent.com/itdoginfo/allow-domains/{SHA}/Russia/'
            if url == prefix + 'inside-raw.lst':
                return inside
            if url == prefix + 'outside-raw.lst':
                if isinstance(outside, Exception):
                    raise outside
                return outside
            raise AssertionError('unexpected or unpinned upstream URL: ' + url)
        return fetch

    def test_replaces_both_exactly_including_removals_and_preserves_overlays(self):
        self.sync.sync(self.root, fetch=self.fetcher())
        self.assertEqual((self.root / 'Russia/inside-raw.lst').read_bytes(), INSIDE)
        self.assertEqual((self.root / 'Russia/outside-raw.lst').read_bytes(), OUTSIDE)
        self.assertEqual((self.root / 'force-direct.lst').read_bytes(), b'signed bytes\n')
        self.assertEqual((self.root / 'force-direct.lst.sig').read_bytes(), b'signature\n')
        metadata = json.loads((self.root / 'Russia/provenance.json').read_text())
        self.assertEqual(metadata['upstream_commit'], SHA)
        self.assertEqual(metadata['upstream_committed_at'], '2026-09-10T09:00:00Z')
        self.assertEqual(metadata['files']['outside-raw.lst']['sha256'], hashlib.sha256(OUTSIDE).hexdigest())
        self.assertEqual(metadata['files']['outside-raw.lst']['entries'], 2)

    def test_partial_download_does_not_overwrite_either_list_or_provenance(self):
        before = self.snapshot()
        with self.assertRaises(OSError):
            self.sync.sync(self.root, fetch=self.fetcher(outside=OSError('download failed')))
        self.assertEqual(self.snapshot(), before)

    def test_invalid_payloads_leave_the_whole_snapshot_unchanged(self):
        invalid = [b'', b'\n', b'<html>error</html>\n', b'https://example.com\n',
                   b'example.com:443\n', b'-bad.ru\n', b'bad-.ru\n', b'a..ru\n',
                   b'example.com\nexample.com\n', b'.ua\nua\n', b'EXAMPLE.COM\nexample.com\n',
                   b'\xff\n', b'1.2.3.4\n', b'a.ru\n\n', b' a.ru\n',
                   b'a' * 64 + b'.ru\n', b'a' * 2_000_001]
        for payload in invalid:
            with self.subTest(payload=payload[:70]):
                before = self.snapshot()
                with self.assertRaises(ValueError):
                    self.sync.sync(self.root, fetch=self.fetcher(outside=payload))
                self.assertEqual(self.snapshot(), before)

    def test_entry_limit_prevents_an_unbounded_publication(self):
        before = self.snapshot()
        data = ''.join(f'd{i}.ru\n' for i in range(10_001)).encode()
        with self.assertRaises(ValueError):
            self.sync.sync(self.root, fetch=self.fetcher(inside=data))
        self.assertEqual(self.snapshot(), before)

    def test_unchanged_snapshot_is_a_noop(self):
        self.assertTrue(self.sync.sync(self.root, fetch=self.fetcher()))
        before = self.snapshot()
        self.assertFalse(self.sync.sync(self.root, fetch=self.fetcher()))
        self.assertEqual(self.snapshot(), before)

    def test_bad_upstream_revision_cannot_form_download_urls(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.sync.sync(self.root, fetch=lambda *_: b'{"sha":"main/../../other"}')
        self.assertEqual(self.snapshot(), before)

    def test_truncated_http_body_is_rejected_even_if_last_line_is_valid(self):
        response = io.BytesIO(b'example.com\n')
        response.headers = {'Content-Length': '100'}
        with patch.object(self.sync, 'urlopen', return_value=response):
            with self.assertRaises(ValueError):
                self.sync.download('https://example.org/list', 2_000_000)

    def test_download_enforces_byte_limit_before_parsing(self):
        response = io.BytesIO(b'a' * 101)
        response.headers = {}
        with patch.object(self.sync, 'urlopen', return_value=response):
            with self.assertRaises(ValueError):
                self.sync.download('https://example.org/list', 100)


if __name__ == '__main__':
    unittest.main()
