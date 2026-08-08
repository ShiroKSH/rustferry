#!/usr/bin/env python3
"""Validate versions and exact internal dependency requirements before release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
IGNORED_PARTS = {".git", ".goal3", "node_modules", "target"}
EXPECTED_PUBLISHABLE_PACKAGES = frozenset(
    {
        "cargo-ferry",
        "rustferry",
        "rustferry-android",
        "rustferry-apple",
        "rustferry-codegen",
        "rustferry-core",
        "rustferry-github",
        "rustferry-remote",
    }
)
EXPECTED_NON_PUBLISHABLE_PACKAGES = frozenset({"rustferry-worker-macos"})


def read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def manifest_paths(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("Cargo.toml")
        if not IGNORED_PARTS.intersection(path.relative_to(root).parts)
    )


def dependency_tables(document: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for name in DEPENDENCY_TABLES:
        table = document.get(name)
        if isinstance(table, dict):
            yield table
    for target in document.get("target", {}).values():
        if not isinstance(target, dict):
            continue
        for name in DEPENDENCY_TABLES:
            table = target.get(name)
            if isinstance(table, dict):
                yield table
    workspace_table = document.get("workspace", {}).get("dependencies")
    if isinstance(workspace_table, dict):
        yield workspace_table


def dependency_identity(alias: str, value: Any) -> tuple[str, str | None, bool]:
    if isinstance(value, str):
        return alias, value, False
    if not isinstance(value, dict):
        return alias, None, False
    package = value.get("package", alias)
    version = value.get("version")
    return package, version if isinstance(version, str) else None, value.get("workspace") is True


def validate(root: Path, expected_version: str) -> tuple[list[str], int]:
    failures: list[str] = []
    if not SEMVER.fullmatch(expected_version):
        return [f"invalid semantic version: {expected_version}"], 0

    workspace_manifest = read_toml(root / "Cargo.toml")
    workspace = workspace_manifest.get("workspace", {})
    actual_workspace_version = workspace.get("package", {}).get("version")
    if actual_workspace_version != expected_version:
        failures.append(
            f"Cargo.toml workspace version is {actual_workspace_version!r}, expected {expected_version!r}"
        )

    internal_packages: set[str] = set()
    publishable_packages: set[str] = set()
    non_publishable_packages: set[str] = set()
    member_manifests: list[Path] = []
    for member in workspace.get("members", []):
        manifest = root / member / "Cargo.toml"
        member_manifests.append(manifest)
        package = read_toml(manifest).get("package", {})
        name = package.get("name")
        if not isinstance(name, str):
            failures.append(f"{manifest.relative_to(root)} has no package name")
            continue
        internal_packages.add(name)
        if package.get("publish") is False:
            non_publishable_packages.add(name)
        else:
            publishable_packages.add(name)
        version = package.get("version")
        if version != {"workspace": True}:
            failures.append(
                f"{manifest.relative_to(root)} must inherit package.version from the workspace"
            )

    if publishable_packages != EXPECTED_PUBLISHABLE_PACKAGES:
        failures.append(
            "publishable workspace packages are "
            f"{sorted(publishable_packages)!r}; expected "
            f"{sorted(EXPECTED_PUBLISHABLE_PACKAGES)!r}"
        )
    if non_publishable_packages != EXPECTED_NON_PUBLISHABLE_PACKAGES:
        failures.append(
            "non-publishable workspace packages are "
            f"{sorted(non_publishable_packages)!r}; expected "
            f"{sorted(EXPECTED_NON_PUBLISHABLE_PACKAGES)!r}"
        )

    expected_requirement = f"={expected_version}"
    workspace_dependencies = workspace.get("dependencies", {})
    checked_edges = 0
    for manifest in manifest_paths(root):
        document = read_toml(manifest)
        for table in dependency_tables(document):
            for alias, value in table.items():
                package, requirement, inherited = dependency_identity(alias, value)
                if package not in internal_packages:
                    continue
                checked_edges += 1
                if inherited:
                    _, requirement, inherited_again = dependency_identity(
                        alias, workspace_dependencies.get(alias)
                    )
                    if inherited_again:
                        requirement = None
                if requirement != expected_requirement:
                    failures.append(
                        f"{manifest.relative_to(root)} dependency {alias!r} on {package!r} "
                        f"uses {requirement!r}; expected {expected_requirement!r}"
                    )

    cargo_lock = read_toml(root / "Cargo.lock")
    for package_name in sorted(internal_packages):
        entries = [
            package
            for package in cargo_lock.get("package", [])
            if package.get("name") == package_name and "source" not in package
        ]
        if len(entries) != 1 or entries[0].get("version") != expected_version:
            versions = [entry.get("version") for entry in entries]
            failures.append(
                f"Cargo.lock workspace package {package_name!r} versions are {versions!r}; "
                f"expected exactly {expected_version!r}"
            )

    package_json_path = root / "editors" / "vscode" / "package.json"
    package_lock_path = root / "editors" / "vscode" / "package-lock.json"
    package_json = json.loads(package_json_path.read_text(encoding="utf-8"))
    package_lock = json.loads(package_lock_path.read_text(encoding="utf-8"))
    extension_name = package_json.get("name")
    checks = {
        "package.json version": package_json.get("version"),
        "package-lock.json version": package_lock.get("version"),
        "package-lock.json root package version": package_lock.get("packages", {})
        .get("", {})
        .get("version"),
    }
    for label, actual in checks.items():
        if actual != expected_version:
            failures.append(f"{label} is {actual!r}, expected {expected_version!r}")
    if package_lock.get("name") != extension_name:
        failures.append("package-lock.json name does not match package.json")
    if package_lock.get("packages", {}).get("", {}).get("name") != extension_name:
        failures.append("package-lock.json root package name does not match package.json")

    if not member_manifests:
        failures.append("workspace has no release packages")
    if checked_edges == 0:
        failures.append("no internal dependency edges were checked")
    return failures, checked_edges


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version")
    args = parser.parse_args()
    expected_version = args.expected_version
    if expected_version is None:
        expected_version = read_toml(ROOT / "Cargo.toml")["workspace"]["package"]["version"]
    failures, checked_edges = validate(ROOT, expected_version)
    if failures:
        print("release contract failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(
        f"release contract passed: version {expected_version}; "
        f"{checked_edges} exact internal dependency edges"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
