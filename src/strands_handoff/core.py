"""High-level session export, branching, inspection, diff, and reporting."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import SessionFormatError
from .pack import LoadedPack, load_pack, sha256_file, write_pack
from .redaction import RedactionReport, redact_text, redact_value

UPSTREAM_REPOSITORY = "strands-agents/harness-sdk"
UPSTREAM_URL = "https://github.com/strands-agents/harness-sdk"
UPSTREAM_COMMIT = "3e3859e9c68fffc31c23e2f67b10037bc95493e2"
DEFAULT_MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
_NAMESPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TEXT_SUFFIXES = {
    ".csv",
    ".html",
    ".json",
    ".log",
    ".md",
    ".py",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def _validate_identifier(value: str, label: str) -> str:
    if not value or value in {".", ".."} or any(character in value for character in "/\\\0"):
        raise SessionFormatError(f"invalid {label}: {value!r}")
    return value


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SessionFormatError(f"invalid JSON file: {path}") from error


def _decode_pack_json(raw: bytes, name: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SessionFormatError(f"invalid JSON in pack: {name}") from error
    if not isinstance(value, dict):
        raise SessionFormatError(f"JSON object required in pack: {name}")
    return value


def _source_session_dir(storage_dir: Path, session_id: str) -> Path:
    session_id = _validate_identifier(session_id, "session id")
    storage = storage_dir.expanduser().resolve()
    candidate = storage / f"session_{session_id}"
    if candidate.is_symlink():
        raise SessionFormatError(f"session directory may not be a symlink: {candidate}")
    if not candidate.is_dir():
        raise SessionFormatError(f"session directory not found: {candidate}")
    return candidate


def _prepare_session_json(value: Any, relative: Path, report: RedactionReport) -> Any:
    if not isinstance(value, dict):
        raise SessionFormatError(f"Strands session JSON must be an object: {relative}")
    if relative.name.startswith("message_") and value.get("redact_message") is not None:
        value = dict(value)
        value["message"] = value["redact_message"]
        report.counts["strands_guardrail_message"] += 1
    return redact_value(value, report)


def _collect_session_files(session_dir: Path, report: RedactionReport) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(session_dir.rglob("*")):
        if path.is_symlink():
            raise SessionFormatError(f"symlinks are not exported: {path}")
        if path.is_dir():
            continue
        if not path.is_file() or path.suffix.lower() != ".json":
            raise SessionFormatError(f"unsupported file in session directory: {path}")
        relative = path.relative_to(session_dir)
        value = _prepare_session_json(_load_json(path), relative, report)
        files[f"session/{relative.as_posix()}"] = _json_bytes(value)
    if "session/session.json" not in files:
        raise SessionFormatError("session.json is missing")
    return files


def _artifact_file_bytes(
    path: Path,
    *,
    report: RedactionReport,
    allow_binary: bool,
    max_file_bytes: int,
) -> tuple[bytes, bool]:
    size = path.stat().st_size
    if size > max_file_bytes:
        raise SessionFormatError(f"artifact exceeds the {max_file_bytes}-byte file limit: {path}")
    raw = path.read_bytes()
    if path.suffix.lower() == ".json":
        try:
            return _json_bytes(redact_value(json.loads(raw), report)), False
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise SessionFormatError(f"invalid JSON artifact: {path}") from error
    if path.suffix.lower() in _TEXT_SUFFIXES:
        try:
            return redact_text(raw.decode("utf-8"), report).encode(), False
        except UnicodeDecodeError as error:
            raise SessionFormatError(f"text artifact is not UTF-8: {path}") from error
    if not allow_binary:
        raise SessionFormatError(
            f"binary artifact requires --allow-binary-artifacts because its contents cannot be redacted: {path}"
        )
    return raw, True


def _collect_artifacts(
    artifact_dirs: list[tuple[str, Path]],
    *,
    files: dict[str, bytes],
    report: RedactionReport,
    allow_binary: bool,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_namespaces: set[str] = set()
    for namespace, root_input in artifact_dirs:
        if not _NAMESPACE.fullmatch(namespace) or namespace in seen_namespaces:
            raise SessionFormatError(f"invalid or duplicate artifact namespace: {namespace!r}")
        seen_namespaces.add(namespace)
        root_candidate = root_input.expanduser()
        if root_candidate.is_symlink():
            raise SessionFormatError(f"artifact directory may not be a symlink: {root_candidate}")
        root = root_candidate.resolve()
        if not root.is_dir():
            raise SessionFormatError(f"artifact directory not found: {root}")
        file_count = 0
        total_bytes = 0
        binary_files = 0
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise SessionFormatError(f"symlinks are not exported: {path}")
            if path.is_dir():
                continue
            relative = path.relative_to(root)
            filename_report = RedactionReport()
            if redact_text(relative.as_posix(), filename_report) != relative.as_posix():
                raise SessionFormatError(f"artifact path contains sensitive data; rename it before export: {relative}")
            data, is_binary = _artifact_file_bytes(
                path,
                report=report,
                allow_binary=allow_binary,
                max_file_bytes=max_file_bytes,
            )
            files[f"artifacts/{namespace}/{relative.as_posix()}"] = data
            file_count += 1
            total_bytes += len(data)
            binary_files += int(is_binary)
        records.append(
            {
                "namespace": namespace,
                "file_count": file_count,
                "bytes": total_bytes,
                "binary_files_unscanned": binary_files,
            }
        )
    return records


def export_session(
    *,
    storage_dir: Path,
    session_id: str,
    output: Path,
    handoff_session_id: str | None = None,
    artifact_dirs: list[tuple[str, Path]] | None = None,
    allow_binary_artifacts: bool = False,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> dict[str, Any]:
    """Export a Strands FileSessionManager directory to a redacted strandpack."""
    session_dir = _source_session_dir(storage_dir, session_id)
    source_session_json = _load_json(session_dir / "session.json")
    if not isinstance(source_session_json, dict) or source_session_json.get("session_id") != session_id:
        raise SessionFormatError("session.json session_id does not match the requested session")
    identifier_report = RedactionReport()
    if handoff_session_id is None and redact_text(session_id, identifier_report) != session_id:
        raise SessionFormatError("session id contains sensitive data; use --handoff-session-id for the exported pack")
    exported_session_id = _validate_identifier(handoff_session_id or session_id, "handoff session id")

    report = RedactionReport()
    files = _collect_session_files(session_dir, report)
    session_json = _decode_pack_json(files["session/session.json"], "session/session.json")
    session_json["session_id"] = exported_session_id
    files["session/session.json"] = _json_bytes(session_json)
    artifacts = _collect_artifacts(
        artifact_dirs or [],
        files=files,
        report=report,
        allow_binary=allow_binary_artifacts,
        max_file_bytes=max_artifact_bytes,
    )
    redaction = {"applied": True, "replacement": "<REDACTED>", **report.as_dict()}
    source = {
        "kind": "strands-file-session",
        "layout": "FileSessionManager",
        "session_id": exported_session_id,
        "source_session_id_aliased": exported_session_id != session_id,
        "upstream": {
            "repository": UPSTREAM_REPOSITORY,
            "url": UPSTREAM_URL,
            "inspected_commit": UPSTREAM_COMMIT,
        },
    }
    return write_pack(
        output,
        files=files,
        source=source,
        redaction=redaction,
        artifacts=artifacts,
    )


def _message_details(loaded: LoadedPack) -> tuple[dict[str, int], Counter[str], int, int]:
    agents: dict[str, int] = {}
    roles: Counter[str] = Counter()
    tool_uses = 0
    tool_results = 0
    for name, raw in loaded.files.items():
        path = PurePosixPath(name)
        if len(path.parts) == 4 and path.parts[:2] == ("session", "agents") and path.name == "agent.json":
            value = _decode_pack_json(raw, name)
            agent_id = str(value.get("agent_id", path.parts[2].removeprefix("agent_")))
            agents.setdefault(agent_id, 0)
        if len(path.parts) != 5 or path.parts[:2] != ("session", "agents") or path.parts[3] != "messages":
            continue
        value = _decode_pack_json(raw, name)
        agent_id = path.parts[2].removeprefix("agent_")
        agents[agent_id] = agents.get(agent_id, 0) + 1
        message = value.get("message", {})
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if isinstance(role, str):
            roles[role] += 1
        content = message.get("content", [])
        if isinstance(content, list):
            tool_uses += sum(isinstance(block, dict) and "toolUse" in block for block in content)
            tool_results += sum(isinstance(block, dict) and "toolResult" in block for block in content)
    return dict(sorted(agents.items())), roles, tool_uses, tool_results


def inspect_loaded(loaded: LoadedPack) -> dict[str, Any]:
    """Return a read-only semantic overview of a verified pack."""
    agents, roles, tool_uses, tool_results = _message_details(loaded)
    artifacts = loaded.manifest.get("artifacts", [])
    artifact_files = sum(item.get("file_count", 0) for item in artifacts if isinstance(item, dict))
    artifact_bytes = sum(item.get("bytes", 0) for item in artifacts if isinstance(item, dict))
    source = loaded.manifest.get("source", {})
    return {
        "integrity": "ok",
        "format_version": loaded.manifest.get("format_version"),
        "created_at": loaded.manifest.get("created_at"),
        "session_id": source.get("session_id") if isinstance(source, dict) else None,
        "agents": agents,
        "messages": sum(agents.values()),
        "roles": dict(sorted(roles.items())),
        "tool_uses": tool_uses,
        "tool_results": tool_results,
        "redaction": loaded.manifest.get("redaction", {}),
        "artifacts": {"files": artifact_files, "bytes": artifact_bytes, "namespaces": artifacts},
        "branch": loaded.manifest.get("branch"),
    }


def inspect_pack(path: Path) -> dict[str, Any]:
    """Verify and inspect a pack without writing to the source or destination."""
    return inspect_loaded(load_pack(path))


def branch_pack(
    source_pack: Path,
    output: Path,
    *,
    new_session_id: str,
    agent_id: str | None = None,
    through_message: int | None = None,
) -> dict[str, Any]:
    """Create an isolated full-copy or review-only message-boundary branch."""
    new_session_id = _validate_identifier(new_session_id, "new session id")
    if (agent_id is None) != (through_message is None):
        raise SessionFormatError("--agent-id and --through-message must be used together")
    if through_message is not None and through_message < 0:
        raise SessionFormatError("through-message must be zero or greater")
    if agent_id is not None:
        _validate_identifier(agent_id, "agent id")

    loaded = load_pack(source_pack)
    files = dict(loaded.files)
    session_data = _decode_pack_json(files["session/session.json"], "session/session.json")
    old_session_id = session_data.get("session_id")
    session_data["session_id"] = new_session_id
    files["session/session.json"] = _json_bytes(session_data)

    removed = 0
    if agent_id is not None and through_message is not None:
        prefix = f"session/agents/agent_{agent_id}/messages/message_"
        matching = [name for name in files if name.startswith(prefix) and name.endswith(".json")]
        if not matching:
            raise SessionFormatError(f"agent has no messages in pack: {agent_id}")
        for name in matching:
            message = _decode_pack_json(files[name], name)
            try:
                message_id = int(message.get("message_id", -1))
            except (TypeError, ValueError) as error:
                raise SessionFormatError(f"invalid message id in pack: {name}") from error
            if message_id > through_message:
                del files[name]
                removed += 1

    source = dict(loaded.manifest.get("source", {}))
    source["session_id"] = new_session_id
    source["derived_from_session_id"] = old_session_id
    branch = {
        "parent_pack_sha256": sha256_file(source_pack.expanduser().resolve()),
        "parent_session_id": old_session_id,
        "mode": "review-only-message-boundary" if through_message is not None else "full-session-copy",
        "restorable": through_message is None,
        "removed_messages": removed,
    }
    if through_message is not None:
        branch["checkpoint"] = {"agent_id": agent_id, "through_message": through_message}
    return write_pack(
        output,
        files=files,
        source=source,
        redaction=dict(loaded.manifest.get("redaction", {})),
        artifacts=list(loaded.manifest.get("artifacts", [])),
        branch=branch,
    )


def diff_packs(left_path: Path, right_path: Path) -> dict[str, Any]:
    """Compare file integrity records and semantic message counts between packs."""
    left = load_pack(left_path)
    right = load_pack(right_path)
    left_hashes = _hashes(left)
    right_hashes = _hashes(right)
    left_names = set(left_hashes)
    right_names = set(right_hashes)
    left_inspection = inspect_loaded(left)
    right_inspection = inspect_loaded(right)
    agent_ids = set(left_inspection["agents"]) | set(right_inspection["agents"])
    return {
        "left_session_id": left_inspection["session_id"],
        "right_session_id": right_inspection["session_id"],
        "added": sorted(right_names - left_names),
        "removed": sorted(left_names - right_names),
        "changed": sorted(name for name in left_names & right_names if left_hashes[name] != right_hashes[name]),
        "message_delta": {
            agent_id: right_inspection["agents"].get(agent_id, 0) - left_inspection["agents"].get(agent_id, 0)
            for agent_id in sorted(agent_ids)
        },
    }


def verify_lineage(pack_paths: Sequence[Path]) -> dict[str, Any]:
    """Verify each child pack's recorded parent against an ordered pack chain."""
    if len(pack_paths) < 2:
        raise SessionFormatError("verify-lineage requires at least two packs")

    nodes = []
    for path in pack_paths:
        resolved = path.expanduser().resolve()
        loaded = load_pack(resolved)
        source = loaded.manifest.get("source", {})
        nodes.append(
            {
                "path": str(resolved),
                "sha256": sha256_file(resolved),
                "session_id": source.get("session_id"),
                "derived_from_session_id": source.get("derived_from_session_id"),
                "branch": loaded.manifest.get("branch"),
            }
        )

    links = []
    for parent, child in zip(nodes, nodes[1:], strict=False):
        reasons = []
        branch = child["branch"]
        if not isinstance(branch, dict):
            reasons.append("missing_branch_metadata")
            recorded_sha256 = None
            recorded_session_id = None
        else:
            recorded_sha256 = branch.get("parent_pack_sha256")
            recorded_session_id = branch.get("parent_session_id")
            if recorded_sha256 != parent["sha256"]:
                reasons.append("parent_pack_sha256_mismatch")
            if recorded_session_id != parent["session_id"]:
                reasons.append("parent_session_id_mismatch")
            if child["derived_from_session_id"] != parent["session_id"]:
                reasons.append("derived_session_id_mismatch")
        links.append(
            {
                "parent": parent["path"],
                "child": child["path"],
                "parent_session_id": parent["session_id"],
                "child_session_id": child["session_id"],
                "parent_sha256": parent["sha256"],
                "recorded_parent_sha256": recorded_sha256,
                "recorded_parent_session_id": recorded_session_id,
                "status": "verified" if not reasons else "broken",
                "reasons": reasons,
            }
        )

    failed = sum(link["status"] == "broken" for link in links)
    return {
        "root": nodes[0]["path"],
        "tip": nodes[-1]["path"],
        "summary": {
            "packs": len(nodes),
            "links": len(links),
            "verified": len(links) - failed,
            "failed": failed,
            "valid": failed == 0,
        },
        "links": links,
    }


def _hashes(loaded: LoadedPack) -> dict[str, str]:
    return {record["path"]: record["sha256"] for record in loaded.manifest["files"]}


def summary_markdown(path: Path) -> str:
    """Generate a portable Markdown handoff summary from a verified pack."""
    loaded = load_pack(path)
    details = inspect_loaded(loaded)
    source = loaded.manifest.get("source", {})
    upstream = source.get("upstream", {}) if isinstance(source, dict) else {}
    lines = [
        "# Strands session handoff",
        "",
        f"- Session: `{details['session_id']}`",
        f"- Created: {details['created_at']}",
        f"- Integrity: **{details['integrity']}**",
        f"- Messages: {details['messages']} across {len(details['agents'])} agent(s)",
        f"- Tool uses/results: {details['tool_uses']} / {details['tool_results']}",
        f"- Redactions applied: {details['redaction'].get('total', 0)}",
        f"- Artifacts: {details['artifacts']['files']} file(s), {details['artifacts']['bytes']} byte(s)",
    ]
    if isinstance(upstream, dict) and upstream.get("url"):
        lines.append(f"- Upstream: [{upstream.get('repository')}]({upstream.get('url')})")
    if details["branch"]:
        lines.extend(
            [
                f"- Branch mode: `{details['branch'].get('mode')}`",
                f"- Runtime-restorable branch: `{str(details['branch'].get('restorable')).lower()}`",
            ]
        )
    lines.extend(["", "## Agents", ""])
    for agent_id, count in details["agents"].items():
        lines.append(f"- `{agent_id}`: {count} message(s)")
    lines.extend(["", "## Role counts", ""])
    for role, count in details["roles"].items():
        lines.append(f"- `{role}`: {count}")
    lines.extend(
        [
            "",
            "## Safety note",
            "",
            "This report was generated offline. Verify the pack before extraction. "
            "A message-boundary branch is for review and comparison only; "
            "it is not a faithful rewind of Strands runtime state.",
            "",
        ]
    )
    return "\n".join(lines)
