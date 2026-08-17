# Compatibility reference

## Upstream

- Repository: [`strands-agents/harness-sdk`](https://github.com/strands-agents/harness-sdk)
- Format reference: [`3e3859e9c68fffc31c23e2f67b10037bc95493e2`](https://github.com/strands-agents/harness-sdk/commit/3e3859e9c68fffc31c23e2f67b10037bc95493e2)
- License: Apache-2.0

## Inspected interfaces

The integration is based on the public Python session contracts and on-disk layout in:

- `strands-py/src/strands/session/file_session_manager.py`
- `strands-py/src/strands/session/repository_session_manager.py`
- `strands-py/src/strands/session/session_repository.py`
- `strands-py/src/strands/types/session.py`
- `strands-py/src/strands/session/snapshot_session_manager.py`
- `strands-py/src/strands/storage/local_file_storage.py`

The current exporter supports the message-log layout produced by Python `FileSessionManager`. Strands snapshot storage is a separate mechanism and is not supported.

## Project boundary

This repository is an independently implemented community CLI. It does not vendor the Strands SDK. The CLI:

- Reads a `FileSessionManager` session directory without constructing a manager that may write.
- Applies persisted `redact_message` replacements and a second pass over common credentials and local identities.
- Packages session data and namespaced artifacts in a portable `.strandpack`.
- Records sizes and SHA-256 hashes in a versioned manifest.
- Verifies before inspect, diff, summary, branch, or extraction.
- Creates a full-copy branch under a new session identity without touching the parent.
- Creates explicitly non-restorable message-boundary branches for offline review.
- Extracts only into a new destination with traversal, duplicate-name, symlink, and overwrite defenses.

`strands-handoff` is not affiliated with, maintained by, or endorsed by the Strands Agents maintainers. “Strands” is used only to describe compatibility with the upstream session format.
