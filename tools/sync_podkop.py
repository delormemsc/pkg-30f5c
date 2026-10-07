#!/usr/bin/env python3
"""Mirror both Podkop Russia RAW lists from one immutable upstream revision."""

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.request import Request, urlopen


UPSTREAM = 'itdoginfo/allow-domains'
FILES = ('inside-raw.lst', 'outside-raw.lst')
SUBNET_FILES = ('Subnets/IPv4/meta.lst', 'Subnets/IPv4/telegram.lst')
LOCAL_RANGES = tuple(map(ipaddress.IPv4Network, ('0.0.0.0/8', '10.0.0.0/8',
    '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
    '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/3')))
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
        if len(labels) == 1 and not re.fullmatch(r'[a-zA-Z]{2,24}', domain):
            raise ValueError('invalid single-label suffix')
        if (len(domain) > 253 or not all(LABEL.fullmatch(label) for label in labels)
                or not re.search(r'[a-zA-Z]', labels[-1])):
            raise ValueError('invalid domain suffix')
        normalized = domain.lower()
        if normalized in seen:
            raise ValueError('duplicate domain suffix')
        seen.add(normalized)
    return len(lines)


def validate_subnets(data):
    if not data or len(data) > 256_000:
        raise ValueError('empty or oversized subnet list')
    lines = data.decode('ascii').splitlines()
    if not 1 <= len(lines) <= 4000:
        raise ValueError('subnet count is outside allowed bounds')
    seen = set()
    for value in lines:
        network = ipaddress.IPv4Network(value, strict=True)
        if (network.prefixlen < 8 or str(network) != value or network in seen
                or any(network.overlaps(local) for local in LOCAL_RANGES)):
            raise ValueError('invalid subnet')
        seen.add(network)
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
    for name in FILES + SUBNET_FILES:
        path = f'Russia/{name}' if name in FILES else name
        url = f'https://raw.githubusercontent.com/{UPSTREAM}/{sha}/{path}'
        data = fetch(url, MAX_BYTES if name in FILES else 256_000)
        count = validate(data) if name in FILES else validate_subnets(data)
        contents[path] = data
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
                (root / name).read_bytes() == data for name, data in contents.items())):
            return False
    except (OSError, ValueError):
        pass
    provenance['mirrored_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    contents['Russia/provenance.json'] = (json.dumps(provenance, indent=2) + '\n').encode()

    # All fetches and validation finish before touching published files. Git is
    # the publication transaction: the workflow never commits after any failure.
    with tempfile.TemporaryDirectory(prefix='.podkop-', dir=root) as stage:
        for name, data in contents.items():
            (Path(stage) / name).parent.mkdir(parents=True, exist_ok=True)
            (Path(stage) / name).write_bytes(data)
        destination.mkdir(exist_ok=True)
        for name in contents:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            os.replace(Path(stage) / name, root / name)
    return True


if __name__ == '__main__':
    changed = sync(Path(__file__).resolve().parents[1])
    print('Podkop snapshot updated.' if changed else 'Podkop snapshot unchanged.')
