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
overlays. The mirror does not edit, regenerate or sign them. Their existing
manual signing/publication process and Ed25519 keys remain separate from Actions.
The workflow stages only the three named files in `Russia/`.

## Local verification

Requires Python 3.11 or newer; no third-party packages:

```sh
python3 -m unittest discover -s tools -p 'test_*.py' -v
python3 tools/sync_podkop.py
git diff -- Russia/
```

The first command is offline. The second reads the public upstream and updates
the local working tree only; it never commits or pushes.
