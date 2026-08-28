# strands-handoff

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/OkkBtc/strands-handoff/actions/workflows/ci.yml/badge.svg)](https://github.com/OkkBtc/strands-handoff/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Offline session handoff with redaction and integrity checks for [Strands Agents](https://github.com/strands-agents/harness-sdk).

`strands-handoff` packages Python `FileSessionManager` sessions into portable `.strandpack` files for review, transfer, and comparison. It runs locally without calling an LLM or uploading session data.

Redaction is best-effort and the current implementation has not undergone an independent security audit. It does not replace a comprehensive secret or PII scanner; review every pack before transferring it.

## Features

- **Best-effort redacted export:** honors persisted Strands `redact_message` replacements, then redacts sensitive keys and several common credential, token, email, and home-directory patterns.
- **Integrity checks:** records file sizes and SHA-256 digests in a versioned manifest and verifies them before inspection or extraction.
- **Batch verification:** checks multiple packs in one command, optionally fingerprints each complete archive, and reports every result before returning a combined exit status.
- **Quiet CI verification:** suppresses successful verification output while retaining failure diagnostics and exit status.
- **Read-only inspection:** summarizes agents, messages, roles, tool calls, redaction counts, and packaged artifacts without modifying the source session.
- **Verified file inventory:** optionally lists every packaged path, byte size, and manifest SHA-256 after integrity checks pass.
- **Verified manifest audit:** exposes the complete validated manifest without manually opening the ZIP archive.
- **Transfer fingerprint:** hashes the complete `.strandpack` file and can require a received pack to match an expected SHA-256.
- **Authenticated transfer record:** creates and verifies a detached HMAC-SHA256 record using a shared key kept in an environment variable.
- **Session branches:** creates a full copy under a new session ID or a non-restorable message-boundary branch for offline review.
- **Lineage verification:** validates every parent digest and session identity in an ordered, multi-generation pack derivation chain.
- **Structured diff:** reports added, removed, and changed files plus per-agent message-count changes, with an optional CI-ready difference exit code.
- **Handoff summaries:** generates a Markdown report from a verified pack.
- **Namespaced artifacts:** packages tool outputs under explicit namespaces with file-count and byte-usage metadata.
- **Automation-friendly output:** emits JSON summaries for export, verification, inspection, diff, and extraction workflows.
- **Extraction preview:** validates the pack and reports the exact target session directory before writing anything.
- **Defensive extraction:** rejects path traversal, duplicate entries, symlinks, unsupported top-level paths, unlisted files, size mismatches, and digest mismatches.

## Install

Python 3.10+ is required. The runtime has no third-party dependencies.

```bash
git clone https://github.com/OkkBtc/strands-handoff.git
cd strands-handoff
python -m venv .venv
source .venv/bin/activate
python -m pip install .
strands-handoff --version
```

## Quick start

Export a session created by Strands `FileSessionManager`:

```bash
strands-handoff export \
  --storage-dir ~/.strands/sessions \
  --session-id support-123 \
  --output support-123.strandpack
```

The source directory is only read. The exporter rejects symlinks and unsupported non-JSON session files.

For a machine-readable result containing the resolved pack path, packaged file count, redaction count, and artifact metadata:

```bash
strands-handoff export \
  --storage-dir ~/.strands/sessions \
  --session-id support-123 \
  --output support-123.strandpack \
  --json > export-result.json
```

If the source session ID contains an account or customer identifier, replace it inside the pack without renaming the source directory:

```bash
strands-handoff export \
  --storage-dir ~/.strands/sessions \
  --session-id account-123 \
  --handoff-session-id case-001 \
  --output case-001.strandpack
```

Verify and preview without extracting:

```bash
strands-handoff verify support-123.strandpack
strands-handoff verify support-123.strandpack --json
strands-handoff inspect support-123.strandpack
strands-handoff inspect support-123.strandpack --json
```

Audit the exact packaged paths and create a fingerprint for transfer records:

```bash
strands-handoff inspect support-123.strandpack --files
strands-handoff inspect support-123.strandpack \
  --files \
  --sha256 \
  --manifest \
  --json > inventory.json
```

`--files` reports the verified manifest path, size, and SHA-256 for every
payload file. `--sha256` hashes the exact `.strandpack` archive bytes, so the
value can be compared before and after a copy or upload. Neither digest
authenticates the creator or replaces a signature.

`--manifest` adds the complete verified manifest, including source compatibility,
redaction totals, Artifact metadata, branch metadata, and file records. With
`--json` it is available under the `manifest` key; text output prints a separate
JSON block. The manifest contains metadata and paths, so review it before
sharing even though pack contents are not included.

After receiving a pack, verify its internal manifest and the sender-provided
complete-file fingerprint together:

```bash
strands-handoff verify received.strandpack \
  --expect-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

`--expect-sha256` accepts one pack and a 64-character hexadecimal digest. It
prints both fingerprints and returns status `1` when the verified pack bytes do
not match; JSON output includes `fingerprint_match`. The expected digest must be
shared through a trusted channel if it is intended to provide authenticity.

When sender and receiver share a random secret through a secret manager, create
a detached authentication record for the exact pack bytes:

```bash
strands-handoff authenticate support-123.strandpack \
  --key-env STRANDPACK_HMAC_KEY \
  --output support-123.strandpack.auth.json

strands-handoff verify received.strandpack \
  --auth-record support-123.strandpack.auth.json \
  --key-env STRANDPACK_HMAC_KEY
```

The environment value must be base64 that decodes to at least 32 random bytes;
the key itself is never written to the record or command output. `authenticate`
first verifies the pack, refuses to overwrite an existing record, and creates
the record with owner-only permissions. `verify` checks pack integrity before
using constant-time HMAC comparison. The record contains a pack SHA-256 and an
HMAC-SHA256 tag, so it can authenticate possession of the shared key as well as
detect changed bytes. HMAC is symmetric: it does not provide public-key sender
identity, key distribution, key rotation, or replay protection.

Verify a batch before transfer or archival:

```bash
strands-handoff verify support-123.strandpack support-124.strandpack
strands-handoff verify support-123.strandpack support-124.strandpack \
  --sha256 \
  --json > verification.json
```

Every supplied pack is checked even when an earlier one fails. The command exits
with status `1` if any pack fails verification. `--sha256` adds a
`pack_sha256` fingerprint for each verified archive, allowing one batch result
to serve as both an integrity record and a before/after transfer checklist. A
pack fingerprint detects byte changes but does not authenticate its creator.

For CI steps that only need the exit status, suppress successful pack output:

```bash
strands-handoff verify support-123.strandpack support-124.strandpack --quiet
```

`--quiet` prints nothing when every pack passes. If verification fails, it still
prints the failed pack diagnostics and returns status `1`, while successful
entries stay hidden. It cannot be combined with `--json`, and it does not stop
the command from checking every supplied pack.

Generate a Markdown handoff report:

```bash
strands-handoff summary support-123.strandpack --output HANDOFF.md
```

Create a full-copy branch under a new session ID:

```bash
strands-handoff branch support-123.strandpack \
  --new-session-id support-123-qa \
  --output support-123-qa.strandpack
```

Create a review-only branch ending at one agent message boundary:

```bash
strands-handoff branch support-123.strandpack \
  --new-session-id support-123-review \
  --agent-id triage-agent \
  --through-message 12 \
  --output support-123-review.strandpack
```

Verify a multi-generation derivation chain before archiving or approving it:

```bash
strands-handoff verify-lineage \
  support-123.strandpack \
  support-123-qa.strandpack \
  support-123-review.strandpack \
  --json
```

The command first verifies every pack's manifest and file digests, then checks
each child against the preceding parent using `parent_pack_sha256`,
`parent_session_id`, and `derived_from_session_id`. It returns status `1` for a
missing, reordered, or mismatched derivation link and status `2` for an invalid
pack or invocation. Lineage proves that the supplied files form the recorded
derivation sequence; it does not authenticate who created them. Use the HMAC
authentication record separately when shared-key sender authentication is
required.

Compare two packs without replaying a model:

```bash
strands-handoff diff support-123.strandpack support-123-review.strandpack
strands-handoff diff support-123.strandpack support-123-review.strandpack --json
strands-handoff diff support-123.strandpack support-123-review.strandpack \
  --exit-code
```

By default, `diff` returns status `0` after a successful comparison even when it
reports changes. `--exit-code` keeps status `0` for equal payloads and returns
status `1` when files were added, removed, or changed, which makes the command
usable as a CI gate. Invalid packs still return status `2`.

Validate a full-copy pack and preview its exact extraction target without writing:

```bash
strands-handoff extract support-123-qa.strandpack \
  --destination ./received-sessions \
  --dry-run \
  --json
```

The plan includes the resolved destination root, `session_<id>` directory, and
the number of files that would be written. It verifies pack integrity,
restorability metadata, the session ID, and destination conflicts. A dry run
does not create the destination or temporary directories, but it cannot prove
that enough disk space or final write permissions will be available.

Extract the pack after reviewing the plan:

```bash
strands-handoff extract support-123-qa.strandpack --destination ./received-sessions
strands-handoff extract support-123-qa.strandpack \
  --destination ./received-sessions \
  --json
```

The result contains `received-sessions/session_support-123-qa/`. Extraction only validates and writes the storage tree; neither a dry run nor extraction launches Strands or verifies runtime restoration. Restoration requires a compatible Strands version, the same agent identity, and compatible agent configuration. Existing destinations are never overwritten. Review-only message-boundary branches cannot be extracted as runtime sessions.

## Artifact packaging

Each artifact directory must have an explicit namespace:

```bash
strands-handoff export \
  --storage-dir ~/.strands/sessions \
  --session-id support-123 \
  --artifact research=./artifacts/research \
  --artifact screenshots=./artifacts/screenshots \
  --output support-123.strandpack
```

UTF-8 text and JSON artifacts are redacted. Artifact paths matching recognized sensitive patterns are rejected. Other file types are treated as binary and blocked by default because their contents cannot be reliably scanned. Include reviewed binary artifacts only with `--allow-binary-artifacts`; the manifest records how many binary files were unscanned. Each artifact is limited to 25 MiB by default and can be adjusted with `--max-artifact-mib`.

## Pack format

A `.strandpack` is a ZIP container with:

```text
manifest.json
session/session.json
session/agents/agent_<id>/agent.json
session/agents/agent_<id>/messages/message_<n>.json
artifacts/<namespace>/...
```

The manifest records the compatibility reference, redaction counts, artifact usage, file sizes, and SHA-256 digests. Verification detects files that no longer match the manifest; it does not authenticate the pack's creator or replace a digital signature.

## Compatibility and limitations

- The current implementation supports the Python `FileSessionManager` message-log layout described in [UPSTREAM.md](UPSTREAM.md). Strands snapshot storage is not supported.
- A full-copy branch preserves the exported session metadata and messages under a new session ID. Successful restoration still depends on compatible Strands, agent IDs, tools, and state structure.
- A message-boundary branch removes later message files for offline review and comparison. Because `agent.json` contains latest-state metadata, this is not a runtime rewind and is marked `restorable: false`.
- Pattern-based redaction is not a comprehensive secret or PII scanner. Review a pack before sharing it, especially when binary artifacts are enabled.
- The CLI does not execute tools, replay model calls, upload packs, or implement Strands runtime orchestration handoff.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
pyright
pytest
python -m build
```

All tests use synthetic sessions and run without provider credentials.

## Security

Do not attach real session packs, tokens, or customer data to public issues. See [SECURITY.md](SECURITY.md) for private reporting and the threat boundary.
Keep HMAC keys in a secret manager, distribute them separately from packs and authentication records, and rotate them according to your own access policy.

## License and upstream

`strands-handoff` is licensed under Apache-2.0. It is an independent community project and is not affiliated with or endorsed by the Strands Agents maintainers. The compatibility reference and attribution are documented in [UPSTREAM.md](UPSTREAM.md) and [NOTICE](NOTICE).
