#!/usr/bin/env python3
"""Reject unsafe, unlicensed, or private material in Cargo package archives."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import tomllib


TEXT_SUFFIXES = frozenset(
    {
        ".css",
        ".h",
        ".html",
        ".java",
        ".js",
        ".json",
        ".md",
        ".mjs",
        ".plist",
        ".rs",
        ".slint",
        ".svg",
        ".toml",
        ".tpl",
        ".ts",
        ".txt",
        ".xml",
        ".yml",
        ".yaml",
    }
)
REQUIRED_LICENSES = {
    "LICENSE-APACHE": "53395048c41d220b8e2652e20c3f4749cab8e9ae9af7a8f591755bbba7b7325d",
    "LICENSE-MIT": "8d6e17950f6e01812c6489c0a2dfd7f129650c424e3b0b6986fee8ab67d8e45a",
}
TEXT_NAMES = frozenset(
    {"Cargo.lock", "Cargo.toml", "Cargo.toml.orig", *REQUIRED_LICENSES}
)
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 10_000
SCAN_CHUNK_BYTES = 64 * 1024
SCAN_OVERLAP_BYTES = 4 * 1024
FORBIDDEN_CONTENT = (
    re.compile(rb"/Users/[A-Za-z0-9._-]+/"),
    re.compile(rb"/home/[A-Za-z0-9._-]+/"),
    re.compile(rb"[A-Z]:\\Users\\[^\\]+\\"),
    re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
)
FORBIDDEN_SUFFIXES = (
    ".cer",
    ".der",
    ".jks",
    ".key",
    ".keystore",
    ".mobileprovision",
    ".p12",
    ".p8",
    ".pem",
    ".pfx",
)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-sources",
        action="store_true",
        help="compile unpacked package sources and verify the packaged CLI handshake",
    )
    parser.add_argument(
        "--cargo",
        default=os.environ.get("CARGO", "cargo"),
        help="cargo executable used by --check-sources",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        help="Cargo target directory used by --check-sources",
    )
    parser.add_argument("archives", nargs="+", type=Path)
    return parser.parse_args()


def check_archive(archive):
    failures = []
    license_digests = {}
    roots = set()
    member_names = set()
    total_member_bytes = 0
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        return [f"archive exceeds {MAX_ARCHIVE_BYTES}-byte compressed-size bound"]
    with tarfile.open(archive, mode="r:gz") as package:
        for member_index, member in enumerate(package, start=1):
            if member_index > MAX_MEMBERS:
                failures.append(f"archive exceeds {MAX_MEMBERS}-member bound")
                break
            if member.name in member_names:
                failures.append(f"duplicate member path: {member.name}")
            member_names.add(member.name)
            path = PurePosixPath(member.name)
            unsafe_path = (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in member.name
                or re.match(r"^[A-Za-z]:", member.name) is not None
            )
            if unsafe_path:
                failures.append(f"unsafe member path: {member.name}")
            elif path.parts:
                roots.add(path.parts[0])
            if any(part in {"node_modules", "target"} for part in path.parts):
                failures.append(f"generated dependency/build path: {member.name}")
            lowered = member.name.lower()
            if lowered.endswith(FORBIDDEN_SUFFIXES) or "/.env" in lowered:
                failures.append(f"credential-like member: {member.name}")
            if member.issym() or member.islnk():
                failures.append(f"link member is not allowed: {member.name}")
            elif not (member.isfile() or member.isdir()):
                failures.append(f"unsupported member type: {member.name}")
            if not member.isfile():
                continue
            if member.size < 0:
                failures.append(f"member has negative size: {member.name}")
                continue
            total_member_bytes += member.size
            if total_member_bytes > MAX_TOTAL_MEMBER_BYTES:
                failures.append(
                    f"archive exceeds {MAX_TOTAL_MEMBER_BYTES}-byte uncompressed-size bound"
                )
                break
            if member.size > MAX_MEMBER_BYTES:
                failures.append(
                    f"member exceeds {MAX_MEMBER_BYTES}-byte scan bound: {member.name}"
                )
                continue
            if (
                path.name in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES
            ) and member.size > MAX_TEXT_BYTES:
                failures.append(f"text member exceeds scan bound: {member.name}")
            source = package.extractfile(member)
            if source is None:
                failures.append(f"could not read member: {member.name}")
                continue
            with source:
                digest, contains_private_material, scanned_bytes = scan_member(source)
            if scanned_bytes != member.size:
                failures.append(
                    f"member size changed while scanning: {member.name} "
                    f"(expected {member.size}, read {scanned_bytes})"
                )
            if len(path.parts) == 2 and path.name in REQUIRED_LICENSES:
                license_digests[path.name] = digest
            if contains_private_material:
                failures.append(f"private material in member: {member.name}")
    if len(roots) != 1:
        failures.append(f"expected one archive root, found: {sorted(roots)}")
    for name, expected_digest in REQUIRED_LICENSES.items():
        actual_digest = license_digests.get(name)
        if actual_digest is None:
            failures.append(f"missing root dual-license file: {name}")
        elif actual_digest != expected_digest:
            failures.append(f"unexpected {name} content digest: {actual_digest}")
    return failures


def scan_member(source):
    digest = hashlib.sha256()
    tail = b""
    scanned_bytes = 0
    contains_private_material = False
    while chunk := source.read(SCAN_CHUNK_BYTES):
        scanned_bytes += len(chunk)
        digest.update(chunk)
        window = tail + chunk
        if any(pattern.search(window) for pattern in FORBIDDEN_CONTENT):
            contains_private_material = True
        tail = window[-SCAN_OVERLAP_BYTES:]
    return digest.hexdigest(), contains_private_material, scanned_bytes


def check_package_sources(archives, cargo, target_dir=None):
    """Compile exact unpacked package sources without repository path dependencies."""
    with tempfile.TemporaryDirectory(prefix="rustferry-package-sources-") as temporary:
        workspace = Path(temporary)
        packages = {}
        for archive in archives:
            package_root = extract_archive(archive, workspace)
            with (package_root / "Cargo.toml").open("rb") as manifest_file:
                manifest = tomllib.load(manifest_file)
            package_name = manifest.get("package", {}).get("name")
            if not isinstance(package_name, str) or not package_name:
                return [f"{archive}: normalized Cargo.toml has no package name"]
            if package_name in packages:
                return [f"duplicate package name in source gate: {package_name}"]
            packages[package_name] = package_root

        (workspace / "Cargo.toml").write_text(
            source_workspace_manifest(packages, workspace), encoding="utf-8"
        )
        environment = os.environ.copy()
        environment.pop("CARGO_FERRY_RUNTIME_PATH", None)
        if target_dir is not None:
            environment["CARGO_TARGET_DIR"] = str(target_dir.resolve())
        command = [
            cargo,
            "test",
            "--workspace",
            "--all-targets",
            "--no-run",
            "--manifest-path",
            str(workspace / "Cargo.toml"),
        ]
        try:
            subprocess.run(command, cwd=workspace, env=environment, check=True)
        except FileNotFoundError:
            return [f"cargo executable was not found: {cargo}"]
        except subprocess.CalledProcessError as error:
            return [f"unpacked package source compilation failed with {error.returncode}"]
        handshake_command = [
            cargo,
            "run",
            "--quiet",
            "--package",
            "cargo-ferry",
            "--",
            "ide",
            "handshake",
            "--json",
        ]
        try:
            handshake = subprocess.run(
                handshake_command,
                cwd=workspace,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return [f"cargo executable was not found: {cargo}"]
        except subprocess.CalledProcessError as error:
            return [f"packaged cargo-ferry handshake failed with {error.returncode}"]
        failures = validate_packaged_handshake(handshake.stdout)
        if failures:
            return failures
    return []


def validate_packaged_handshake(source):
    """Require registry runtime readiness from an executable built from a Cargo archive."""
    try:
        document = json.loads(source)
    except json.JSONDecodeError as error:
        return [f"packaged cargo-ferry handshake returned invalid JSON: {error.msg}"]
    expected = {"source": "registry", "usable": True}
    if document.get("runtime_dependency") != expected:
        return [
            "packaged cargo-ferry handshake did not prove the exact registry runtime contract"
        ]
    return []


def extract_archive(archive, destination):
    """Extract a previously checked archive without links or path traversal."""
    with tarfile.open(archive, mode="r:gz") as package:
        members = package.getmembers()
        roots = {PurePosixPath(member.name).parts[0] for member in members if member.name}
        if len(roots) != 1:
            raise ValueError(f"archive does not have one package root: {archive}")
        root = roots.pop()
        for member in members:
            relative = PurePosixPath(member.name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = package.extractfile(member)
            if source is None:
                raise ValueError(f"could not extract archive member: {member.name}")
            with source, target.open("xb") as output:
                while chunk := source.read(SCAN_CHUNK_BYTES):
                    output.write(chunk)
    return destination / root


def source_workspace_manifest(packages, workspace):
    """Build a temporary workspace that patches internal crates to extracted sources."""
    member_paths = [
        package.relative_to(workspace).as_posix()
        for package in sorted(packages.values())
    ]
    lines = [
        "[workspace]",
        f"members = {json.dumps(member_paths)}",
        'resolver = "2"',
        "",
        "[patch.crates-io]",
    ]
    for name, package in sorted(packages.items()):
        relative = package.relative_to(workspace).as_posix()
        lines.append(f"{json.dumps(name)} = {{ path = {json.dumps(relative)} }}")
    return "\n".join(lines) + "\n"


def main():
    args = parse_args()
    failures = []
    for archive in args.archives:
        if not archive.is_file():
            failures.append(f"missing archive: {archive}")
            continue
        for failure in check_archive(archive):
            failures.append(f"{archive}: {failure}")
    if not failures and args.check_sources:
        failures.extend(
            check_package_sources(args.archives, args.cargo, args.target_dir)
        )
    if failures:
        raise SystemExit("Release archive check failed:\n- " + "\n- ".join(failures))
    print(f"Release archive check passed: {len(args.archives)} archives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
