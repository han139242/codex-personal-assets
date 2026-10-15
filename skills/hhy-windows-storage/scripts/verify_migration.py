"""Read-only inventory and content verification for ordinary static directories.

Only a new manifest/report file is written. No source or destination files are
copied, removed, overwritten, or reconfigured. Python 3.10+; standard library.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import sys


def is_reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def plain_root(path: Path) -> Path:
    path = path.absolute()
    for ancestor in reversed((path, *path.parents)):
        if ancestor.exists() or ancestor.is_symlink():
            if is_reparse(ancestor):
                raise ValueError(f"Linked/reparse directory is unsupported: {ancestor}")
    if not path.is_dir():
        raise ValueError(f"Directory does not exist: {path}")
    return path.resolve()


def relative_name(value: str, allow_root: bool = False) -> str:
    if allow_root and value == ".":
        return value
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("Invalid relative path in manifest")
    parts = PurePosixPath(value)
    if (parts.is_absolute() or PureWindowsPath(value).drive
            or ".." in parts.parts or ":" in value
            or str(parts) != value or value == "."):
        raise ValueError("Unsafe relative path in manifest")
    return value


def stable_hash(path: Path) -> tuple[int, str]:
    if is_reparse(path):
        raise ValueError("Linked/reparse file is unsupported")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("Only regular files are supported")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("File changed during hashing")
    if is_reparse(path):
        raise ValueError("File became a reparse point during hashing")
    return after.st_size, digest.hexdigest()


def snapshot(root: Path) -> dict:
    root = plain_root(Path(root))
    errors: list[dict] = []
    files: list[dict] = []
    directories: list[str] = []

    def onerror(error: OSError) -> None:
        errors.append({"path": str(error.filename), "error": str(error)})

    for current, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
        current_path = Path(current)
        try:
            if is_reparse(current_path):
                raise ValueError("Reparse directory encountered")
            directories.append(current_path.relative_to(root).as_posix())
        except (OSError, ValueError) as error:
            errors.append({"path": str(current_path), "error": str(error)})
            dirs[:] = []
            continue
        safe_dirs = []
        for name in sorted(dirs):
            path = current_path / name
            try:
                relative_name(path.relative_to(root).as_posix())
                if is_reparse(path):
                    raise ValueError("Linked/reparse directory is unsupported")
                safe_dirs.append(name)
            except (OSError, ValueError) as error:
                errors.append({"path": str(path), "error": str(error)})
        dirs[:] = safe_dirs
        for name in sorted(names):
            path = current_path / name
            try:
                rel = relative_name(path.relative_to(root).as_posix())
                size, digest = stable_hash(path)
                files.append({"path": rel, "size": size, "sha256": digest})
            except (OSError, ValueError) as error:
                errors.append({"path": str(path), "error": str(error)})
    return {
        "schema_version": 1, "source": str(root),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "complete": not errors, "files": sorted(files, key=lambda item: item["path"]),
        "directories": sorted(directories), "errors": errors,
    }


def validate_manifest(manifest: dict) -> None:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("Unsupported manifest schema")
    if manifest.get("complete") is not True or manifest.get("errors") != []:
        raise ValueError("Incomplete inventory cannot authorize migration")
    if not isinstance(manifest.get("source"), str) or not Path(manifest["source"]).is_absolute():
        raise ValueError("Manifest requires the absolute source directory")
    if not isinstance(manifest.get("files"), list) or not isinstance(manifest.get("directories"), list):
        raise ValueError("Missing files or directories")
    seen = set()
    for entry in manifest["files"]:
        rel = relative_name(entry["path"])
        identity = rel.casefold() if os.name == "nt" else rel
        if identity in seen:
            raise ValueError("Duplicate file path in manifest")
        seen.add(identity)
        if type(entry.get("size")) is not int or entry["size"] < 0:
            raise ValueError("Invalid file size")
        digest = entry.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid SHA256")
    dirs = set()
    for rel in manifest["directories"]:
        relative_name(rel, allow_root=True)
        identity = rel.casefold() if os.name == "nt" else rel
        if identity in dirs or identity in seen:
            raise ValueError("Duplicate or conflicting directory path")
        dirs.add(identity)
    if "." not in dirs:
        raise ValueError("Root directory is absent in manifest")
    for entry in manifest["files"]:
        parent = str(PurePosixPath(entry["path"]).parent)
        identity = parent.casefold() if os.name == "nt" else parent
        if identity not in dirs:
            raise ValueError("File parent absent from manifest")


def compare(expected: dict, actual: dict, allow_extra: bool) -> dict:
    expected_files = {item["path"]: item for item in expected["files"]}
    actual_files = {item["path"]: item for item in actual["files"]}
    missing = sorted(set(expected_files) - set(actual_files))
    extra_files = sorted(set(actual_files) - set(expected_files))
    changed = [name for name in sorted(set(expected_files) & set(actual_files))
               if any(expected_files[name][key] != actual_files[name][key]
                      for key in ("size", "sha256"))]
    missing_dirs = sorted(set(expected["directories"]) - set(actual["directories"]))
    extra_dirs = sorted(set(actual["directories"]) - set(expected["directories"]))
    passed = (actual["complete"] and not missing and not changed and not missing_dirs
              and (allow_extra or not (extra_files or extra_dirs)))
    return {"passed": bool(passed), "missing_files": missing, "changed_files": changed,
            "extra_files": extra_files, "missing_directories": missing_dirs,
            "extra_directories": extra_dirs, "scan_errors": actual["errors"]}


def verify(manifest: dict, destination: Path, check_source: bool = False,
           allow_extra: bool = False) -> dict:
    validate_manifest(manifest)
    destination = plain_root(Path(destination))
    source_path = Path(manifest["source"]).resolve()
    if (destination.is_relative_to(source_path) or source_path.is_relative_to(destination)):
        raise ValueError("Source and destination must not overlap")
    destination_snapshot = snapshot(destination)
    result = compare(manifest, destination_snapshot, allow_extra)
    source_result = None
    if check_source:
        source_result = compare(manifest, snapshot(Path(manifest["source"])), False)
    return {"schema_version": 1,
            "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source": manifest["source"], "destination": str(destination),
            "read_only": True, "source_checked": check_source, "allow_extra": allow_extra,
            "passed": result["passed"] and (source_result is None or source_result["passed"]),
            "expected_file_count": len(manifest["files"]),
            "expected_bytes": sum(item["size"] for item in manifest["files"]),
            "destination_check": result, "source_check": source_result}


def write_new_json(path: Path, data: dict, roots: list[Path]) -> None:
    resolved = path.resolve()
    for root in roots:
        if resolved.is_relative_to(root.resolve()):
            raise ValueError("Manifest/report must be outside source and destination")
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    snap = commands.add_parser("snapshot")
    snap.add_argument("source", type=Path)
    snap.add_argument("manifest", type=Path)
    check = commands.add_parser("verify")
    check.add_argument("manifest", type=Path)
    check.add_argument("destination", type=Path)
    check.add_argument("report", type=Path)
    check.add_argument("--check-source", action="store_true")
    check.add_argument("--allow-extra", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "snapshot":
            data = snapshot(args.source)
            write_new_json(args.manifest, data, [args.source])
            passed = data["complete"]
            count = len(data["files"])
        else:
            data_in = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
            data = verify(data_in, args.destination, args.check_source, args.allow_extra)
            write_new_json(args.report, data, [args.destination, Path(data_in["source"])])
            passed = data["passed"]
            count = data["expected_file_count"]
        print(json.dumps({"passed": passed, "files": count, "read_only": True}))
        return 0 if passed else 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
