from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest

from strands_handoff.core import branch_pack, diff_packs, export_session, inspect_pack, summary_markdown
from strands_handoff.errors import PackIntegrityError, SessionFormatError
from strands_handoff.pack import MANIFEST_PATH, extract_pack, load_pack


def _export(session_storage: Path, destination: Path, **kwargs: object) -> Path:
    export_session(storage_dir=session_storage, session_id="demo", output=destination, **kwargs)
    return destination


def test_export_is_redacted_and_integrity_checked(session_storage: Path, tmp_path: Path) -> None:
    pack = _export(session_storage, tmp_path / "demo.strandpack")
    loaded = load_pack(pack)
    combined = b"\n".join(loaded.files.values())

    assert b"sk-proj-" not in combined
    assert b"alice@example.com" not in combined
    assert b"/Users/alice" not in combined
    assert b"original unsafe text" not in combined
    assert b"guardrail replacement" in combined
    assert loaded.manifest["redaction"]["total"] == 4


def test_inspect_reports_agents_messages_tools_and_roles(session_storage: Path, tmp_path: Path) -> None:
    pack = _export(session_storage, tmp_path / "demo.strandpack")

    details = inspect_pack(pack)

    assert details["integrity"] == "ok"
    assert details["session_id"] == "demo"
    assert details["agents"] == {"researcher": 3}
    assert details["roles"] == {"assistant": 1, "user": 2}
    assert details["tool_uses"] == 1


def test_inspect_is_read_only(session_storage: Path, tmp_path: Path) -> None:
    pack = _export(session_storage, tmp_path / "demo.strandpack")
    before = pack.stat().st_mtime_ns

    inspect_pack(pack)

    assert pack.stat().st_mtime_ns == before


def test_detects_tampered_member(session_storage: Path, tmp_path: Path) -> None:
    original = _export(session_storage, tmp_path / "demo.strandpack")
    tampered = tmp_path / "tampered.strandpack"
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(tampered, "w") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename.endswith("message_0.json"):
                data += b"tampered"
            target.writestr(info, data)

    with pytest.raises(PackIntegrityError, match="integrity check failed"):
        load_pack(tampered)


def test_rejects_archive_traversal(tmp_path: Path) -> None:
    malicious = tmp_path / "malicious.strandpack"
    with zipfile.ZipFile(malicious, "w") as archive:
        archive.writestr("../outside", b"bad")
        archive.writestr(MANIFEST_PATH, json.dumps({"format": "strandpack", "format_version": 1, "files": []}))

    with pytest.raises(PackIntegrityError, match="unsafe archive member"):
        load_pack(malicious)


def test_full_branch_has_new_identity_and_is_restorable(session_storage: Path, tmp_path: Path) -> None:
    source = _export(session_storage, tmp_path / "demo.strandpack")
    branch = tmp_path / "branch.strandpack"

    manifest = branch_pack(source, branch, new_session_id="demo-branch")
    loaded = load_pack(branch)
    session = json.loads(loaded.files["session/session.json"])

    assert session["session_id"] == "demo-branch"
    assert manifest["branch"]["mode"] == "full-session-copy"
    assert manifest["branch"]["restorable"] is True
    assert inspect_pack(source)["session_id"] == "demo"


def test_message_boundary_branch_is_review_only(session_storage: Path, tmp_path: Path) -> None:
    source = _export(session_storage, tmp_path / "demo.strandpack")
    branch = tmp_path / "review.strandpack"

    manifest = branch_pack(
        source,
        branch,
        new_session_id="demo-review",
        agent_id="researcher",
        through_message=1,
    )

    assert inspect_pack(branch)["agents"] == {"researcher": 2}
    assert manifest["branch"]["restorable"] is False
    assert manifest["branch"]["removed_messages"] == 1
    with pytest.raises(PackIntegrityError, match="review-only"):
        extract_pack(branch, tmp_path / "must-not-run")


def test_diff_reports_branch_changes(session_storage: Path, tmp_path: Path) -> None:
    source = _export(session_storage, tmp_path / "demo.strandpack")
    branch = tmp_path / "review.strandpack"
    branch_pack(source, branch, new_session_id="demo-review", agent_id="researcher", through_message=1)

    difference = diff_packs(source, branch)

    assert difference["message_delta"] == {"researcher": -1}
    assert "session/agents/agent_researcher/messages/message_2.json" in difference["removed"]
    assert "session/session.json" in difference["changed"]


def test_summary_has_upstream_and_safety_boundary(session_storage: Path, tmp_path: Path) -> None:
    pack = _export(session_storage, tmp_path / "demo.strandpack")

    summary = summary_markdown(pack)

    assert "strands-agents/harness-sdk" in summary
    assert "not a faithful rewind" in summary
    assert "`researcher`: 3 message(s)" in summary


def test_extract_creates_new_strands_storage_root(session_storage: Path, tmp_path: Path) -> None:
    pack = _export(session_storage, tmp_path / "demo.strandpack")
    destination = tmp_path / "received"

    result = extract_pack(pack, destination)

    assert result == destination
    assert (destination / "session_demo" / "session.json").is_file()
    assert (destination / "strandpack-manifest.json").is_file()
    with pytest.raises(PackIntegrityError, match="already exists"):
        extract_pack(pack, destination)


def test_artifacts_are_namespaced_and_text_redacted(session_storage: Path, tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "report.txt").write_text("owner@example.com", encoding="utf-8")
    pack = tmp_path / "demo.strandpack"

    export_session(
        storage_dir=session_storage,
        session_id="demo",
        output=pack,
        artifact_dirs=[("research", artifacts)],
    )
    loaded = load_pack(pack)

    assert loaded.files["artifacts/research/report.txt"] == b"<REDACTED>"
    assert loaded.manifest["artifacts"][0]["namespace"] == "research"


def test_binary_artifacts_require_explicit_opt_in(session_storage: Path, tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "image.png").write_bytes(b"\x89PNG\x00")

    with pytest.raises(SessionFormatError, match="allow-binary-artifacts"):
        export_session(
            storage_dir=session_storage,
            session_id="demo",
            output=tmp_path / "blocked.strandpack",
            artifact_dirs=[("images", artifacts)],
        )


def test_handoff_session_id_hides_sensitive_source_identity(session_storage: Path, tmp_path: Path) -> None:
    source = session_storage / "session_demo"
    renamed = session_storage / "session_user@example.com"
    source.rename(renamed)
    session_file = renamed / "session.json"
    session_data = json.loads(session_file.read_text(encoding="utf-8"))
    session_data["session_id"] = "user@example.com"
    session_file.write_text(json.dumps(session_data), encoding="utf-8")
    pack = tmp_path / "aliased.strandpack"

    export_session(
        storage_dir=session_storage,
        session_id="user@example.com",
        handoff_session_id="case-001",
        output=pack,
    )
    loaded = load_pack(pack)
    combined = json.dumps(loaded.manifest).encode() + b"\n" + b"\n".join(loaded.files.values())

    assert b"user@example.com" not in combined
    assert inspect_pack(pack)["session_id"] == "case-001"
    assert loaded.manifest["source"]["source_session_id_aliased"] is True


def test_artifact_symlink_root_is_rejected(session_storage: Path, tmp_path: Path) -> None:
    artifacts = tmp_path / "real-artifacts"
    artifacts.mkdir()
    (artifacts / "note.txt").write_text("safe", encoding="utf-8")
    link = tmp_path / "artifact-link"
    try:
        os.symlink(artifacts, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    with pytest.raises(SessionFormatError, match="may not be a symlink"):
        export_session(
            storage_dir=session_storage,
            session_id="demo",
            output=tmp_path / "demo.strandpack",
            artifact_dirs=[("notes", link)],
        )


def test_rejects_session_symlink(session_storage: Path, tmp_path: Path) -> None:
    target = session_storage / "session_demo" / "extra.json"
    target.write_text("{}", encoding="utf-8")
    link = session_storage / "session_demo" / "linked.json"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    with pytest.raises(SessionFormatError, match="symlinks are not exported"):
        export_session(storage_dir=session_storage, session_id="demo", output=tmp_path / "demo.strandpack")
