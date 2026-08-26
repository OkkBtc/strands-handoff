"""Creation, validation, and safe extraction of .strandpack archives."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import stat
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import PackIntegrityError

FORMAT_NAME = "strandpack"
FORMAT_VERSION = 1
MANIFEST_PATH = "manifest.json"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class LoadedPack:
    """A verified strandpack held in memory."""

    manifest: dict[str, Any]
    files: dict[str, bytes]


@dataclass(frozen=True)
class ExtractionPlan:
    """A verified extraction target that has not been written yet."""

    pack: Path
    destination: Path
    session_directory: Path
    file_count: int
    _loaded: LoadedPack = field(repr=False, compare=False)

    def execute(self) -> Path:
        """Write this verified plan without re-reading the pack."""
        _execute_extraction(self)
        return self.destination


def utc_now() -> str:
    """Return a stable UTC timestamp for manifests."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    """Return the hexadecimal SHA-256 digest for bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return the hexadecimal SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hmac_sha256_file(path: Path, key: bytes) -> str:
    """Return an HMAC-SHA256 tag for the exact bytes of a file."""
    digest = hmac.new(key, digestmod=hashlib.sha256)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_member_name(name: str) -> None:
    if not name or "\\" in name:
        raise PackIntegrityError(f"unsafe archive member: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PackIntegrityError(f"unsafe archive member: {name!r}")


def _file_records(files: dict[str, bytes]) -> list[dict[str, Any]]:
    records = []
    for name, data in sorted(files.items()):
        _validate_member_name(name)
        if name == MANIFEST_PATH:
            raise PackIntegrityError(f"{MANIFEST_PATH} is reserved")
        records.append({"path": name, "sha256": sha256_bytes(data), "size": len(data)})
    return records


def write_pack(
    output: Path,
    *,
    files: dict[str, bytes],
    source: dict[str, Any],
    redaction: dict[str, Any],
    artifacts: list[dict[str, Any]] | None = None,
    branch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically write a new strandpack, refusing to overwrite existing data."""
    output = output.expanduser().resolve()
    if output.exists():
        raise PackIntegrityError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "format": FORMAT_NAME,
        "format_version": FORMAT_VERSION,
        "created_at": utc_now(),
        "source": source,
        "redaction": redaction,
        "artifacts": artifacts or [],
        "files": _file_records(files),
    }
    if branch is not None:
        manifest["branch"] = branch

    manifest_data = (json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(files.items()):
                archive.writestr(name, data)
            archive.writestr(MANIFEST_PATH, manifest_data)
        os.chmod(temporary, 0o600)
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return manifest


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def load_pack(path: Path) -> LoadedPack:
    """Load and fully verify a strandpack before returning any content."""
    path = path.expanduser().resolve()
    if not path.is_file():
        raise PackIntegrityError(f"pack does not exist: {path}")

    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise PackIntegrityError("archive contains duplicate member names")
            for info in infos:
                _validate_member_name(info.filename)
                if info.is_dir() or _is_symlink(info):
                    raise PackIntegrityError(f"unsupported archive member: {info.filename}")
                if info.file_size > MAX_MEMBER_BYTES:
                    raise PackIntegrityError(f"archive member exceeds size limit: {info.filename}")
            if sum(info.file_size for info in infos) > MAX_ARCHIVE_BYTES:
                raise PackIntegrityError("archive exceeds uncompressed size limit")
            if names.count(MANIFEST_PATH) != 1:
                raise PackIntegrityError(f"archive must contain exactly one {MANIFEST_PATH}")
            manifest_info = archive.getinfo(MANIFEST_PATH)
            if manifest_info.file_size > MAX_MANIFEST_BYTES:
                raise PackIntegrityError("manifest exceeds size limit")
            manifest = json.loads(archive.read(MANIFEST_PATH))
            data = {name: archive.read(name) for name in names if name != MANIFEST_PATH}
    except (zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise PackIntegrityError(f"invalid strandpack: {error}") from error

    if not isinstance(manifest, dict):
        raise PackIntegrityError("manifest must be a JSON object")
    if manifest.get("format") != FORMAT_NAME or manifest.get("format_version") != FORMAT_VERSION:
        raise PackIntegrityError("unsupported strandpack format or version")
    source = manifest.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("session_id"), str):
        raise PackIntegrityError("manifest source must contain a session id")
    if not isinstance(manifest.get("redaction"), dict) or not isinstance(manifest.get("artifacts"), list):
        raise PackIntegrityError("manifest redaction or artifacts metadata is invalid")
    records = manifest.get("files")
    if not isinstance(records, list):
        raise PackIntegrityError("manifest files must be a list")

    expected: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise PackIntegrityError("manifest contains an invalid file record")
        name = record["path"]
        _validate_member_name(name)
        if PurePosixPath(name).parts[0] not in {"session", "artifacts"}:
            raise PackIntegrityError(f"unsupported top-level member: {name}")
        if name in expected:
            raise PackIntegrityError(f"manifest contains duplicate file record: {name}")
        expected[name] = record
    if set(expected) != set(data):
        raise PackIntegrityError("manifest file list does not match archive contents")
    if "session/session.json" not in data:
        raise PackIntegrityError("archive is missing session/session.json")
    for name, contents in data.items():
        record = expected[name]
        if record.get("size") != len(contents) or record.get("sha256") != sha256_bytes(contents):
            raise PackIntegrityError(f"integrity check failed for {name}")
    return LoadedPack(manifest=manifest, files=data)


def prepare_extraction(path: Path, destination: Path) -> ExtractionPlan:
    """Verify a pack and return its extraction plan without writing anything."""
    loaded = load_pack(path)
    branch = loaded.manifest.get("branch")
    if isinstance(branch, dict) and branch.get("restorable") is False:
        raise PackIntegrityError("review-only message-boundary branches cannot be extracted as runtime sessions")
    source = loaded.manifest.get("source", {})
    session_id = source.get("session_id") if isinstance(source, dict) else None
    if not isinstance(session_id, str) or not session_id or any(char in session_id for char in "/\\"):
        raise PackIntegrityError("manifest has an invalid session id")

    destination = destination.expanduser().resolve()
    if destination.exists():
        raise PackIntegrityError(f"destination already exists: {destination}")
    return ExtractionPlan(
        pack=path.expanduser().resolve(),
        destination=destination,
        session_directory=destination / f"session_{session_id}",
        file_count=len(loaded.files) + 1,
        _loaded=loaded,
    )


def _execute_extraction(plan: ExtractionPlan) -> None:
    if plan.destination.exists():
        raise PackIntegrityError(f"destination already exists: {plan.destination}")
    plan.destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = plan.destination.parent / f".{plan.destination.name}.tmp-{uuid.uuid4().hex}"
    temporary.mkdir(mode=0o700)
    try:
        for name, contents in plan._loaded.files.items():
            relative = PurePosixPath(name)
            if relative.parts[0] == "session":
                target = temporary / plan.session_directory.name / Path(*relative.parts[1:])
            elif relative.parts[0] == "artifacts":
                target = temporary / Path(*relative.parts)
            else:
                raise PackIntegrityError(f"unsupported top-level member: {name}")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(contents)
            os.chmod(target, 0o600)
        manifest_copy = temporary / "strandpack-manifest.json"
        manifest_copy.write_text(
            json.dumps(plan._loaded.manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(manifest_copy, 0o600)
        if plan.destination.exists():
            raise PackIntegrityError(f"destination already exists: {plan.destination}")
        os.replace(temporary, plan.destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def extract_pack(path: Path, destination: Path) -> Path:
    """Verify and extract a pack into a new Strands-compatible storage root."""
    return prepare_extraction(path, destination).execute()
