from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from strands_handoff.cli import main


def test_cli_end_to_end(session_storage: Path, tmp_path: Path, capsys) -> None:
    pack = tmp_path / "demo.strandpack"
    assert (
        main(
            [
                "export",
                "--storage-dir",
                str(session_storage),
                "--session-id",
                "demo",
                "--output",
                str(pack),
            ]
        )
        == 0
    )
    assert main(["verify", str(pack)]) == 0
    assert main(["inspect", str(pack), "--json"]) == 0
    assert '"session_id": "demo"' in capsys.readouterr().out


def test_cli_export_json_returns_machine_readable_summary(session_storage: Path, tmp_path: Path, capsys) -> None:
    pack = tmp_path / "demo.strandpack"
    artifacts = tmp_path / "research"
    artifacts.mkdir()
    (artifacts / "notes.txt").write_text("synthetic notes", encoding="utf-8")

    assert (
        main(
            [
                "export",
                "--storage-dir",
                str(session_storage),
                "--session-id",
                "demo",
                "--artifact",
                f"research={artifacts}",
                "--output",
                str(pack),
                "--json",
            ]
        )
        == 0
    )

    result = json.loads(capsys.readouterr().out)
    assert result["pack"] == str(pack.resolve())
    assert result["files"] > 0
    assert isinstance(result["redactions"], int)
    assert result["artifacts"] == [
        {
            "binary_files_unscanned": 0,
            "bytes": len("synthetic notes"),
            "file_count": 1,
            "namespace": "research",
        }
    ]


def test_cli_inspect_optional_inventory_and_fingerprint(session_storage: Path, tmp_path: Path, capsys) -> None:
    pack = tmp_path / "demo.strandpack"
    assert (
        main(
            [
                "export",
                "--storage-dir",
                str(session_storage),
                "--session-id",
                "demo",
                "--output",
                str(pack),
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert main(["inspect", str(pack), "--json"]) == 0
    default = json.loads(capsys.readouterr().out)
    assert "files" not in default
    assert "pack_sha256" not in default
    assert "manifest" not in default

    assert main(["inspect", str(pack), "--files", "--sha256", "--manifest", "--json"]) == 0
    details = json.loads(capsys.readouterr().out)
    assert details["pack_sha256"] == hashlib.sha256(pack.read_bytes()).hexdigest()
    assert [record["path"] for record in details["files"]] == sorted(record["path"] for record in details["files"])
    assert all(set(record) == {"path", "size", "sha256"} for record in details["files"])
    assert any(record["path"] == "session/session.json" for record in details["files"])
    assert details["manifest"]["format"] == "strandpack"
    assert details["manifest"]["source"]["session_id"] == "demo"
    assert details["manifest"]["files"] == details["files"]

    assert main(["inspect", str(pack), "--files", "--sha256", "--manifest"]) == 0
    output = capsys.readouterr().out
    assert f"Pack SHA-256: {details['pack_sha256']}" in output
    assert "session/session.json" in output
    assert "Manifest:" in output
    assert '"format": "strandpack"' in output


def test_cli_verify_returns_one_for_tampered_pack(session_storage: Path, tmp_path: Path, capsys) -> None:
    pack = tmp_path / "demo.strandpack"
    assert main(["export", "--storage-dir", str(session_storage), "--session-id", "demo", "--output", str(pack)]) == 0
    bad = tmp_path / "bad.strandpack"
    with zipfile.ZipFile(pack) as source, zipfile.ZipFile(bad, "w") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "session/session.json":
                value = json.loads(data)
                value["session_id"] = "changed"
                data = json.dumps(value).encode()
            target.writestr(info, data)

    assert main(["verify", str(bad)]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_cli_verify_multiple_packs_reports_every_result(session_storage: Path, tmp_path: Path, capsys) -> None:
    good = tmp_path / "good.strandpack"
    assert main(["export", "--storage-dir", str(session_storage), "--session-id", "demo", "--output", str(good)]) == 0
    bad = tmp_path / "bad.strandpack"
    with zipfile.ZipFile(good) as source, zipfile.ZipFile(bad, "w") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "session/session.json":
                value = json.loads(data)
                value["session_id"] = "changed"
                data = json.dumps(value).encode()
            target.writestr(info, data)
    capsys.readouterr()

    assert main(["verify", str(good), str(bad), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["summary"] == {"total": 2, "passed": 1, "failed": 1}
    assert [pack["integrity"] for pack in result["packs"]] == ["ok", "failed"]
    assert [pack["pack"] for pack in result["packs"]] == [str(good.resolve()), str(bad.resolve())]

    assert main(["verify", str(good), str(bad)]) == 1
    output = capsys.readouterr().out
    assert f"OK {good.resolve()}" in output
    assert f"FAILED {bad.resolve()}" in output
    assert "Verified 1/2 pack(s); failed=1" in output

    assert main(["verify", str(good), str(bad), "--quiet"]) == 1
    quiet_output = capsys.readouterr().out
    assert str(good.resolve()) not in quiet_output
    assert f"FAILED {bad.resolve()}" in quiet_output
    assert "Verified" not in quiet_output


def test_cli_verify_can_include_pack_fingerprints(session_storage: Path, tmp_path: Path, capsys) -> None:
    first = tmp_path / "first.strandpack"
    second = tmp_path / "second.strandpack"
    assert main(["export", "--storage-dir", str(session_storage), "--session-id", "demo", "--output", str(first)]) == 0
    second.write_bytes(first.read_bytes())
    capsys.readouterr()

    assert main(["verify", str(first), str(second), "--sha256", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    expected = hashlib.sha256(first.read_bytes()).hexdigest()
    assert [pack["pack_sha256"] for pack in result["packs"]] == [expected, expected]

    assert main(["verify", str(first), "--sha256"]) == 0
    assert f"Pack SHA-256: {expected}" in capsys.readouterr().out

    assert main(["verify", str(first), "--sha256", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["pack_sha256"] == expected

    assert main(["verify", str(first), "--quiet"]) == 0
    assert capsys.readouterr().out == ""


def test_cli_verify_can_require_expected_fingerprint(session_storage: Path, tmp_path: Path, capsys) -> None:
    pack = tmp_path / "received.strandpack"
    assert main(["export", "--storage-dir", str(session_storage), "--session-id", "demo", "--output", str(pack)]) == 0
    capsys.readouterr()
    expected = hashlib.sha256(pack.read_bytes()).hexdigest()

    assert main(["verify", str(pack), "--expect-sha256", expected.upper(), "--json"]) == 0
    matched = json.loads(capsys.readouterr().out)
    assert matched["pack_sha256"] == expected
    assert matched["expected_sha256"] == expected
    assert matched["fingerprint_match"] is True

    wrong = ("0" if expected[0] != "0" else "1") + expected[1:]
    assert main(["verify", str(pack), "--expect-sha256", wrong, "--json"]) == 1
    mismatched = json.loads(capsys.readouterr().out)
    assert mismatched["integrity"] == "ok"
    assert mismatched["fingerprint_match"] is False


def test_cli_expected_fingerprint_validates_input_and_pack_count(tmp_path: Path, capsys) -> None:
    with pytest.raises(SystemExit):
        main(["verify", str(tmp_path / "pack.strandpack"), "--expect-sha256", "not-a-digest"])
    assert "64-character hexadecimal" in capsys.readouterr().err

    digest = "0" * 64
    assert (
        main(
            [
                "verify",
                str(tmp_path / "first.strandpack"),
                str(tmp_path / "second.strandpack"),
                "--expect-sha256",
                digest,
            ]
        )
        == 2
    )
    assert "requires exactly one pack" in capsys.readouterr().err

    with pytest.raises(SystemExit):
        main(["verify", str(tmp_path / "pack.strandpack"), "--quiet", "--json"])
    assert "not allowed with argument" in capsys.readouterr().err


def test_cli_diff_exit_code_detects_payload_changes(session_storage: Path, tmp_path: Path, capsys) -> None:
    source = tmp_path / "source.strandpack"
    branch = tmp_path / "branch.strandpack"
    assert main(["export", "--storage-dir", str(session_storage), "--session-id", "demo", "--output", str(source)]) == 0
    assert (
        main(
            [
                "branch",
                str(source),
                "--new-session-id",
                "demo-review",
                "--output",
                str(branch),
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert main(["diff", str(source), str(source), "--exit-code"]) == 0
    capsys.readouterr()
    assert main(["diff", str(source), str(branch), "--exit-code", "--json"]) == 1
    difference = json.loads(capsys.readouterr().out)
    assert "session/session.json" in difference["changed"]


def test_cli_extract_dry_run_then_extract_json(session_storage: Path, tmp_path: Path, capsys) -> None:
    pack = tmp_path / "demo.strandpack"
    assert main(["export", "--storage-dir", str(session_storage), "--session-id", "demo", "--output", str(pack)]) == 0
    capsys.readouterr()
    destination = tmp_path / "missing-parent" / "received"
    command = ["extract", str(pack), "--destination", str(destination), "--json"]

    assert main([*command, "--dry-run"]) == 0
    dry_run = json.loads(capsys.readouterr().out)
    assert dry_run == {
        "destination": str(destination.resolve()),
        "dry_run": True,
        "files": dry_run["files"],
        "pack": str(pack.resolve()),
        "session_directory": str(destination.resolve() / "session_demo"),
    }
    assert dry_run["files"] > 1
    assert not destination.exists()
    assert not destination.parent.exists()

    assert main(command) == 0
    extracted = json.loads(capsys.readouterr().out)
    assert extracted == {**dry_run, "dry_run": False}
    assert (destination / "session_demo" / "session.json").is_file()
    assert sum(path.is_file() for path in destination.rglob("*")) == extracted["files"]

    assert main([*command, "--dry-run"]) == 2
    assert "destination already exists" in capsys.readouterr().err
