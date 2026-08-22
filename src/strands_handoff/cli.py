"""Command-line interface for strands-handoff."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .core import branch_pack, diff_packs, export_session, inspect_loaded, summary_markdown
from .errors import HandoffError, PackIntegrityError, SessionFormatError
from .pack import load_pack, prepare_extraction, sha256_file


def _artifact_spec(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("artifact must use NAMESPACE=PATH")
    namespace, path = value.split("=", 1)
    if not namespace or not path:
        raise argparse.ArgumentTypeError("artifact must use NAMESPACE=PATH")
    return namespace, Path(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strands-handoff",
        description="Export and inspect redacted Strands Agent session handoffs offline.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    export = commands.add_parser("export", help="export a FileSessionManager session")
    export.add_argument("--storage-dir", type=Path, required=True, help="directory containing session_<id>")
    export.add_argument("--session-id", required=True)
    export.add_argument("--handoff-session-id", help="replace a sensitive source session id inside the exported pack")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--json", action="store_true")
    export.add_argument(
        "--artifact",
        type=_artifact_spec,
        action="append",
        default=[],
        metavar="NAMESPACE=PATH",
        help="add an isolated artifact directory; repeat for multiple namespaces",
    )
    export.add_argument(
        "--allow-binary-artifacts",
        action="store_true",
        help="include binary files that cannot be content-redacted",
    )
    export.add_argument("--max-artifact-mib", type=float, default=25.0)

    inspect = commands.add_parser("inspect", help="verify and preview pack metadata")
    inspect.add_argument("pack", type=Path)
    inspect.add_argument("--json", action="store_true")
    inspect.add_argument(
        "--files",
        action="store_true",
        help="include verified file paths, sizes, and SHA-256 digests",
    )
    inspect.add_argument(
        "--sha256",
        action="store_true",
        help="include the SHA-256 fingerprint of the complete pack file",
    )

    verify = commands.add_parser("verify", help="verify manifest and SHA-256 checksums")
    verify.add_argument("pack", type=Path, nargs="+", metavar="PACK", help="one or more pack files")
    verify.add_argument("--json", action="store_true", help="emit machine-readable verification results")

    branch = commands.add_parser("branch", help="create an isolated pack branch")
    branch.add_argument("pack", type=Path)
    branch.add_argument("--output", type=Path, required=True)
    branch.add_argument("--new-session-id", required=True)
    branch.add_argument("--agent-id")
    branch.add_argument("--through-message", type=int)

    diff = commands.add_parser("diff", help="compare two verified packs")
    diff.add_argument("left", type=Path)
    diff.add_argument("right", type=Path)
    diff.add_argument("--json", action="store_true")

    summary = commands.add_parser("summary", help="generate a Markdown handoff report")
    summary.add_argument("pack", type=Path)
    summary.add_argument("--output", type=Path)

    extract = commands.add_parser("extract", help="extract into a new Strands-compatible storage root")
    extract.add_argument("pack", type=Path)
    extract.add_argument("--destination", type=Path, required=True)
    extract.add_argument("--dry-run", action="store_true", help="verify and show the extraction plan without writing")
    extract.add_argument("--json", action="store_true", help="emit a machine-readable extraction plan or result")
    return parser


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


def _run_export(args: argparse.Namespace) -> int:
    if args.max_artifact_mib <= 0:
        raise SessionFormatError("max-artifact-mib must be greater than zero")
    manifest = export_session(
        storage_dir=args.storage_dir,
        session_id=args.session_id,
        output=args.output,
        handoff_session_id=args.handoff_session_id,
        artifact_dirs=args.artifact,
        allow_binary_artifacts=args.allow_binary_artifacts,
        max_artifact_bytes=int(args.max_artifact_mib * 1024 * 1024),
    )
    result = {
        "pack": str(args.output.expanduser().resolve()),
        "files": len(manifest["files"]),
        "redactions": manifest["redaction"]["total"],
        "artifacts": manifest["artifacts"],
    }
    if args.json:
        _print_json(result)
    else:
        print(f"Created {args.output} with {result['files']} file(s); redactions={result['redactions']}")
    return 0


def _run_inspect(args: argparse.Namespace) -> int:
    loaded = load_pack(args.pack)
    details = inspect_loaded(loaded)
    if args.files:
        details["files"] = sorted(
            (
                {
                    "path": record["path"],
                    "size": record["size"],
                    "sha256": record["sha256"],
                }
                for record in loaded.manifest["files"]
            ),
            key=lambda record: record["path"],
        )
    if args.sha256:
        details["pack_sha256"] = sha256_file(args.pack)
    if args.json:
        _print_json(details)
    else:
        print(f"Integrity: {details['integrity']}")
        print(f"Session: {details['session_id']}")
        print(f"Agents/messages: {len(details['agents'])}/{details['messages']}")
        print(f"Redactions: {details['redaction'].get('total', 0)}")
        print(f"Artifacts: {details['artifacts']['files']} file(s)")
        if details["branch"]:
            print(f"Branch: {details['branch'].get('mode')}")
        if args.sha256:
            print(f"Pack SHA-256: {details['pack_sha256']}")
        if args.files:
            print(f"Pack files: {len(details['files'])}")
            for record in details["files"]:
                print(f"  {record['size']:>10} B  {record['path']}  sha256:{record['sha256']}")
    return 0


def _verify_pack(pack: Path) -> dict[str, Any]:
    try:
        loaded = load_pack(pack)
    except PackIntegrityError as error:
        return {
            "pack": str(pack.expanduser().resolve()),
            "integrity": "failed",
            "error": str(error),
        }
    return {
        "pack": str(pack.expanduser().resolve()),
        "integrity": "ok",
        "files": len(loaded.files),
    }


def _run_verify(args: argparse.Namespace) -> int:
    results = [_verify_pack(pack) for pack in args.pack]
    failed = sum(result["integrity"] == "failed" for result in results)
    if len(results) == 1:
        result = {key: value for key, value in results[0].items() if key != "pack"}
        if args.json:
            _print_json(result)
        elif result["integrity"] == "ok":
            print(f"OK: {result['files']} file(s) verified")
        else:
            print(f"FAILED: {result['error']}")
        return int(failed > 0)

    summary = {"total": len(results), "passed": len(results) - failed, "failed": failed}
    if args.json:
        _print_json({"summary": summary, "packs": results})
    else:
        for result in results:
            if result["integrity"] == "ok":
                print(f"OK {result['pack']}: {result['files']} file(s) verified")
            else:
                print(f"FAILED {result['pack']}: {result['error']}")
        print(f"Verified {summary['passed']}/{summary['total']} pack(s); failed={failed}")
    return int(failed > 0)


def _run_branch(args: argparse.Namespace) -> int:
    manifest = branch_pack(
        args.pack,
        args.output,
        new_session_id=args.new_session_id,
        agent_id=args.agent_id,
        through_message=args.through_message,
    )
    print(f"Created {args.output} ({manifest['branch']['mode']})")
    return 0


def _run_diff(args: argparse.Namespace) -> int:
    details = diff_packs(args.left, args.right)
    if args.json:
        _print_json(details)
    else:
        print(f"Sessions: {details['left_session_id']} -> {details['right_session_id']}")
        print(
            f"Files added/removed/changed: {len(details['added'])}/{len(details['removed'])}/{len(details['changed'])}"
        )
        for agent_id, delta in details["message_delta"].items():
            print(f"Message delta [{agent_id}]: {delta:+d}")
    return 0


def _run_summary(args: argparse.Namespace) -> int:
    markdown = summary_markdown(args.pack)
    if args.output is None:
        print(markdown, end="")
        return 0
    output = args.output.expanduser().resolve()
    if output.exists():
        raise PackIntegrityError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    print(f"Created {output}")
    return 0


def _run_extract(args: argparse.Namespace) -> int:
    plan = prepare_extraction(args.pack, args.destination)
    result = {
        "pack": str(plan.pack),
        "destination": str(plan.destination),
        "session_directory": str(plan.session_directory),
        "files": plan.file_count,
        "dry_run": args.dry_run,
    }
    if not args.dry_run:
        plan.execute()
    if args.json:
        _print_json(result)
    elif args.dry_run:
        print(f"Validated {plan.pack}; would extract {plan.file_count} file(s) to {plan.destination}")
    else:
        print(f"Extracted {plan.file_count} file(s) to {plan.destination}")
    return 0


_HANDLERS = {
    "export": _run_export,
    "inspect": _run_inspect,
    "verify": _run_verify,
    "branch": _run_branch,
    "diff": _run_diff,
    "summary": _run_summary,
    "extract": _run_extract,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process status code."""
    args = _parser().parse_args(argv)
    try:
        return _HANDLERS[args.command](args)
    except HandoffError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def entrypoint() -> None:
    """Console-script entry point."""
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
