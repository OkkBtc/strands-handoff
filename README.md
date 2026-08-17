# strands-handoff

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/OkkBtc/strands-handoff/actions/workflows/ci.yml/badge.svg)](https://github.com/OkkBtc/strands-handoff/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Offline session handoff with redaction and integrity checks for [Strands Agents](https://github.com/strands-agents/harness-sdk).

`strands-handoff` packages Python `FileSessionManager` sessions into portable `.strandpack` files for review, transfer, and comparison. It runs locally without calling an LLM or uploading session data.

## Features

- **Redacted export:** honors persisted Strands `redact_message` replacements, then redacts sensitive keys and several common credential, token, email, and home-directory patterns.
- **Integrity checks:** records file sizes and SHA-256 digests in a versioned manifest and verifies them before inspection or extraction.
- **Read-only inspection:** summarizes agents, messages, roles, tool calls, redaction counts, and packaged artifacts without modifying the source session.
- **Session branches:** creates a full copy under a new session ID or a non-restorable message-boundary branch for offline review.
- **Structured diff:** reports added, removed, and changed files plus per-agent message-count changes.
- **Handoff summaries:** generates a Markdown report from a verified pack.
- **Namespaced artifacts:** packages tool outputs under explicit namespaces with file-count and byte-usage metadata.
- **Safe extraction:** rejects path traversal, duplicate entries, symlinks, unsupported top-level paths, unlisted files, size mismatches, and digest mismatches.

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

If the source session ID contains an account or customer identifier, replace it inside the pack without renaming the source directory:

```bash
strands-handoff export \
  --storage-dir ~/.strands/sessions \
  --session-id customer@example.com \
  --handoff-session-id case-001 \
  --output case-001.strandpack
```

Verify and preview without extracting:

```bash
strands-handoff verify support-123.strandpack
strands-handoff inspect support-123.strandpack
strands-handoff inspect support-123.strandpack --json
```

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

Compare two packs without replaying a model:

```bash
strands-handoff diff support-123.strandpack support-123-review.strandpack
strands-handoff diff support-123.strandpack support-123-review.strandpack --json
```

Extract a full-copy pack into a new storage root:

```bash
strands-handoff extract support-123-qa.strandpack --destination ./received-sessions
```

The result contains `received-sessions/session_support-123-qa/`. Restoring it requires a compatible Strands version and the same agent identity and compatible agent configuration. Existing destinations are never overwritten. Review-only message-boundary branches cannot be extracted as runtime sessions.

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

- The current release supports the Python `FileSessionManager` message-log layout described in [UPSTREAM.md](UPSTREAM.md). Strands snapshot storage is not supported.
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

## License and upstream

`strands-handoff` is licensed under Apache-2.0. It is an independent community project and is not affiliated with or endorsed by the Strands Agents maintainers. The compatibility reference and attribution are documented in [UPSTREAM.md](UPSTREAM.md) and [NOTICE](NOTICE).
