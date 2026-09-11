# Policy lists and Podkop mirror

## Russia domain lists

These files are byte-for-byte mirrors of the published RAW lists from
[itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains):

- [Russia/inside-raw.lst](https://raw.githubusercontent.com/delormemsc/pkg-30f5c/main/Russia/inside-raw.lst): services for users inside Russia.
- [Russia/outside-raw.lst](https://raw.githubusercontent.com/delormemsc/pkg-30f5c/main/Russia/outside-raw.lst): Russian services for users outside Russia.
- [Russia/provenance.json](https://raw.githubusercontent.com/delormemsc/pkg-30f5c/main/Russia/provenance.json): immutable upstream commit, commit date, mirror date, source URLs, byte/entry counts and SHA-256 for both files.

The original data, authorship, purpose and any applicable upstream terms remain
with the upstream project; this mirror adds no new license grant. Consult the
[upstream README](https://github.com/itdoginfo/allow-domains/blob/main/README.md)
for source details. No license file was present in the initial upstream snapshot.
Files are copied unmodified: additions and removals follow upstream, without
combining these lists with local policy overrides. A leading dot is permitted
for suffixes such as `.ua`; consumers may normalize it for domain matching.

The `Sync Podkop Russia lists` GitHub Actions workflow runs daily at **09:17 UTC**
and can be started manually using `workflow_dispatch`. GitHub may delay scheduled
runs. Pushes/PRs affecting the workflow or tools run the offline regression tests
only. The upstream generator currently runs on source changes and on Mondays at
08:29 UTC; the mirror consumes its generated RAW artifacts, not its scripts.

Each sync resolves upstream `main` once, downloads both lists using that immutable
commit, and validates both before replacing either file. Limits are 2,000,000
bytes and 10,000 entries per file. Empty lists, invalid suffixes, duplicate
suffixes (case-insensitive, ignoring a leading dot), truncated responses and
failed downloads reject the entire update. Large valid changes are mirrored;
the client applies its own anomaly approval policy against its regional baseline.

Both lists and provenance are published in **one Git commit**. The workflow
serializes concurrent runs. A download, validation or write failure prevents the
publish step, preserving the previously published commit. A conflicting push
fails without force-pushing; the next run retries from current `main`. Unchanged
upstream snapshots produce no commit. A new upstream commit updates provenance
even if the list bytes are unchanged. Failed runs remain visible in Actions.

The RAW files are **unsigned**, matching their upstream trust model. SHA-256 and
provenance record content and origin; they are not cryptographic signatures.
No private signing key is needed by the workflow. Clients should retain their
last accepted regional snapshot or bundled bootstrap when an update fails.

## Signed policy overlays

The root files `force-direct.lst`, `force-tunnel.lst`, `force-tunnel-cidr.lst`
and `blocked.lst`, with their adjacent `.sig` files, are separate signed policy
overlays. The mirror does not edit, regenerate or sign them. Its workflow stages
only the three named files in `Russia/`.

### Signing and publication

Edit the existing policy's source in **`policy/<name>.lst`**. These are editable
sources for the same four overlays, not additional lists or client endpoints.
The root `.lst` and `.lst.sig` files are published artifacts: do not edit them
directly. Clients keep downloading the same root URLs.

Signing happens **on the publisher's own machine, never in GitHub Actions**.
The private Ed25519 key is deliberately absent from this repository's secrets:
GitHub already controls distribution, so a key stored here would let one
compromised account both host and sign `force-direct.lst`, the list that decides
which traffic bypasses the tunnel. Rollback protection does not cover that case,
because whoever can sign can also raise the serial. Keeping the key off GitHub
preserves the separation the signatures exist for.

To publish, on the machine holding the key (default path
`~/.laosarmy/policy-signing-2026-08.key`, public key
`dOidfEll74Z/2vmupX0tEUXjTWCksYPfVXBLkNgSorU=`):

```sh
git pull --ff-only
POLICY_SIGNING_KEY="$(cat ~/.laosarmy/policy-signing-2026-08.key)" python3 tools/publish_policy.py --publish
python3 tools/publish_policy.py --verify-published
git add -- '*.lst' '*.lst.sig' && git commit -m 'policy lists: ...' && git push
```

The publisher:

1. Checks all currently published signatures against the two keys embedded in
   Windows and Apple clients, and validates each source's purpose and entries.
2. Assigns each changed file the verified published serial **plus one**. The
   source serial is a placeholder; it does not need manual increments. Unchanged
   files retain their exact bytes, signatures and serials.
3. Signs with the current Ed25519 key, then verifies every new signature against
   the client keys before writing any published file.
4. Refuses the whole publication on a missing, malformed or different key, on an
   invalid entry and on an exhausted serial, leaving the previous signed root
   files in place. Do not generate a replacement key or commit it anywhere.

Commit each changed list together with its signature, and never separately: a
list without its matching signature is rejected by every client. `.gitattributes`
disables line-ending conversion for signed root files, since even an LF/CRLF
conversion invalidates their signatures. Raw distribution is cached for a few
minutes, so compare SHA-256 of the raw file against the local one before
claiming that an update reached clients. Clients apply a new snapshot on their
next reconnect.

`Validate policy lists` runs the offline tests, rechecks every published
signature and reports sources awaiting signature. It never signs or publishes,
and a pending source does not fail it.

This does not change client region semantics: `force-tunnel.lst` is currently
applied in the Russia region; the outside-Russia profile uses its regional list
and `blocked.lst`, without Russian policy overrides.

## Local verification

Mirror checks require Python 3.11 or newer; no third-party packages:

```sh
python3 -m unittest discover -s tools -p 'test_sync_podkop.py' -v
python3 tools/sync_podkop.py
git diff -- Russia/
```

The first command is offline. The second reads the public upstream and updates
the local working tree only; it never commits or pushes.

Policy checks (Python 3.11+):

```sh
python3 -m pip install -r tools/policy-requirements.txt
python3 -m unittest discover -s tools -p 'test_publish_policy.py' -v
python3 tools/publish_policy.py --check
python3 tools/publish_policy.py --verify-published
```

Tests use ephemeral test keys in temporary directories. Production signatures
are also verified separately with the real public keys; no production private
key is needed for the validation suite. `--publish` requires the secret in the
`POLICY_SIGNING_KEY` environment variable; GitHub Actions is the normal publisher.
