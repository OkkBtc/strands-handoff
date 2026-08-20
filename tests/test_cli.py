from __future__ import annotations

import json
import zipfile
from pathlib import Path

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
