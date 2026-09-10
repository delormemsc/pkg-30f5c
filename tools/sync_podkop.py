#!/usr/bin/env python3
"""Mirror both Podkop Russia RAW lists from one immutable upstream revision."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.request import Request, urlopen


UPSTREAM = 'itdoginfo/allow-domains'
FILES = ('inside-raw.lst', 'outside-raw.lst')
MAX_BYTES = 2_000_000
MAX_ENTRIES = 10_000
LABEL = re.compile(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z')


def download(url, max_bytes):
    request = Request(url, headers={'User-Agent': 'pkg-30f5c-podkop-mirror'})
    with urlopen(request, timeout=30) as response:
        data = response.read(max_bytes + 1)
        expected_length = response.headers.get('Content-Length')
        if expected_length is not None and len(data) != int(expected_length):
            raise ValueError('upstream response length mismatch')
    if len(data) > max_bytes:
        raise ValueError('upstream response exceeds byte limit')
    return data


def validate(data):
    if not data or len(data) > MAX_BYTES:
        raise ValueError('empty or oversized list')
    lines = data.decode('ascii').splitlines()
    if not 1 <= len(lines) <= MAX_ENTRIES:
        raise ValueError('list entry count is outside allowed bounds')
    seen = set()
    for line in lines:
        # Upstream uses a leading dot for TLD suffixes such as .ua.
        domain = line[1:] if line.startswith('.') else line
        labels = domain.split('.')
        if (len(domain) > 253 or not all(LABEL.fullmatch(label) for label in labels)
                or not re.search(r'[a-zA-Z]', labels[-1])):
            raise ValueError('invalid domain suffix')
        normalized = domain.lower()
        if normalized in seen:
            raise ValueError('duplicate domain suffix')
        seen.add(normalized)
    return len(lines)


def sync(root, fetch=download):
    root = Path(root)
    commit = json.loads(fetch(f'https://api.github.com/repos/{UPSTREAM}/commits/main', MAX_BYTES))
    sha = commit.get('sha', '')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('invalid upstream commit SHA')
    committed_at = commit['commit']['committer']['date']
    datetime.fromisoformat(committed_at.replace('Z', '+00:00'))

    contents = {}
    metadata = {}
    for name in FILES:
        url = f'https://raw.githubusercontent.com/{UPSTREAM}/{sha}/Russia/{name}'
        data = fetch(url, MAX_BYTES)
        count = validate(data)
        contents[name] = data
        metadata[name] = {'source_url': url, 'sha256': hashlib.sha256(data).hexdigest(),
                          'bytes': len(data), 'entries': count}

    destination = root / 'Russia'
    provenance_path = destination / 'provenance.json'
    provenance = {'upstream': f'https://github.com/{UPSTREAM}',
                  'upstream_commit': sha, 'upstream_committed_at': committed_at,
                  'files': metadata}
    try:
        previous = json.loads(provenance_path.read_text())
        previous.pop('mirrored_at', None)
        if (previous == provenance and all(
                (destination / name).read_bytes() == data for name, data in contents.items())):
            return False
    except (OSError, ValueError):
        pass
    provenance['mirrored_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    contents['provenance.json'] = (json.dumps(provenance, indent=2) + '\n').encode()

    # All fetches and validation finish before touching published files. Git is
    # the publication transaction: the workflow never commits after any failure.
    with tempfile.TemporaryDirectory(prefix='.podkop-', dir=root) as stage:
        for name, data in contents.items():
            (Path(stage) / name).write_bytes(data)
        destination.mkdir(exist_ok=True)
        for name in contents:
            os.replace(Path(stage) / name, destination / name)
    return True


if __name__ == '__main__':
    changed = sync(Path(__file__).resolve().parents[1])
    print('Podkop snapshot updated.' if changed else 'Podkop snapshot unchanged.')
