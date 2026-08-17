# Security policy

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/OkkBtc/strands-handoff/security/advisories/new). Do not attach a real `.strandpack`, API key, session cookie, customer conversation, or proprietary artifact to a public issue.

When possible, include a minimal synthetic archive, affected version, command, expected behavior, and observed behavior. Replace all credentials and personal information before sending.

## Threat boundary

`strands-handoff` treats source sessions, artifacts, and received packs as untrusted data.

- Source and artifact symlinks are rejected.
- Archive names are checked for traversal, absolute paths, backslashes, duplicates, and symlinks.
- Manifest file lists, byte sizes, and SHA-256 digests must match the archive exactly.
- Per-member, manifest, and total uncompressed size limits reduce accidental archive expansion.
- Extraction only targets a destination that does not yet exist.
- Export redaction reports retain counts, not matched secret values.
- Binary artifacts are blocked unless the operator explicitly accepts that they are unscanned.

Pattern matching cannot guarantee removal of every domain-specific secret, text embedded in binary formats, steganographic content, or credentials split across fields. Always review a pack before sharing it outside the original trust boundary.

## Supported versions

Until a stable release exists, only the default branch is supported.
