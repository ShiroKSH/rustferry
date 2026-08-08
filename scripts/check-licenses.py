#!/usr/bin/env python3
"""Check repository licenses and deterministic dependency inventories."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
METADATA_COMMAND = (
    "cargo",
    "metadata",
    "--locked",
    "--format-version",
    "1",
    "--all-features",
)
ROOT_LICENSES = {
    "LICENSES/SLINT-ROYALTY-FREE-2.0.md": "5167f5056e850419106ab6265efbdca7cba4d99c849d1445ca0bbf6a1e2315fe",
    "LICENSE-APACHE": "53395048c41d220b8e2652e20c3f4749cab8e9ae9af7a8f591755bbba7b7325d",
    "LICENSE-MIT": "8d6e17950f6e01812c6489c0a2dfd7f129650c424e3b0b6986fee8ab67d8e45a",
    "editors/vscode/LICENSE": "8d6e17950f6e01812c6489c0a2dfd7f129650c424e3b0b6986fee8ab67d8e45a",
}
REVIEWED_LICENSE_EXPRESSIONS = frozenset(
    {
        "(MIT OR Apache-2.0) AND Unicode-3.0",
        "0BSD OR MIT OR Apache-2.0",
        "Apache-2.0",
        "Apache-2.0 OR MIT",
        "Apache-2.0 WITH LLVM-exception",
        "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
        "BSD-3-Clause",
        "BSD-3-Clause OR Apache-2.0",
        "BSD-3-Clause OR MIT OR Apache-2.0",
        "MIT",
        "MIT OR Apache-2.0",
        "MIT OR Apache-2.0 OR Zlib",
        "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
        "MIT OR Zlib OR Apache-2.0",
        "MIT/Apache-2.0",
        "MPL-2.0",
        "Unicode-3.0",
        "Unlicense OR MIT",
        "Unlicense/MIT",
        "Zlib",
        "Zlib OR Apache-2.0 OR MIT",
    }
)
NPM_REVIEWED_LICENSE_EXPRESSIONS = frozenset(
    {
        "(BSD-2-Clause OR MIT OR Apache-2.0)",
        "(MIT AND Zlib)",
        "(MIT OR CC0-1.0)",
        "(MIT OR GPL-3.0-or-later)",
        "(MIT OR WTFPL)",
        "0BSD",
        "Apache-2.0",
        "Artistic-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BlueOak-1.0.0",
        "CC-BY-3.0",
        "CC0-1.0",
        "ISC",
        "MIT",
        "MPL-2.0",
        "Python-2.0",
        "SEE LICENSE IN LICENSE.txt",
        "WTFPL",
    }
)
CARGO_INVENTORY = ROOT / "LICENSES" / "cargo-dependencies.json"
CARGO_LOCK = ROOT / "Cargo.lock"
NPM_INVENTORY = ROOT / "LICENSES" / "vscode-development-dependencies.json"
NPM_LOCK = ROOT / "editors" / "vscode" / "package-lock.json"


class LicenseCheckError(Exception):
    """Metadata could not be loaded reliably."""


def load_metadata():
    try:
        result = subprocess.run(
            list(METADATA_COMMAND),
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise LicenseCheckError(f"could not run cargo metadata: {error}") from error

    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise LicenseCheckError(f"cargo metadata failed: {detail}")
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LicenseCheckError(f"cargo metadata returned invalid JSON: {error}") from error
    if not isinstance(metadata.get("packages"), list):
        raise LicenseCheckError("cargo metadata returned no package list")
    return metadata


def normalized_digest(path):
    text = path.read_text(encoding="utf-8")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_cargo_lock():
    try:
        lock = tomllib.loads(CARGO_LOCK.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise LicenseCheckError(f"could not read Cargo.lock: {error}") from error
    if not isinstance(lock.get("package"), list):
        raise LicenseCheckError("Cargo.lock has no package inventory")
    return lock


def cargo_inventory(metadata, lock):
    workspace_members = set(metadata.get("workspace_members", []))
    checksums = {
        (package.get("name"), package.get("version"), package.get("source")): package.get(
            "checksum"
        )
        for package in lock["package"]
    }
    packages = []
    for package in metadata["packages"]:
        if package.get("id") in workspace_members:
            continue
        packages.append(
            {
                "checksum": checksums.get(
                    (package.get("name"), package.get("version"), package.get("source"))
                ),
                "license": package.get("license"),
                "name": package.get("name"),
                "repository": package.get("repository"),
                "source": package.get("source"),
                "version": package.get("version"),
            }
        )
    packages.sort(
        key=lambda package: (
            package["name"] or "",
            package["version"] or "",
            package["source"] or "",
        )
    )
    return {
        "packages": packages,
        "schema_version": 1,
        "source": "Cargo.lock resolved by cargo metadata --locked --all-features",
    }


def load_npm_lock():
    try:
        lock = json.loads(NPM_LOCK.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LicenseCheckError(f"could not read {NPM_LOCK.relative_to(ROOT)}: {error}") from error
    if not isinstance(lock.get("packages"), dict):
        raise LicenseCheckError("VS Code package lock has no package inventory")
    return lock


def npm_inventory(lock):
    packages = []
    for package_path, package in lock["packages"].items():
        if not package_path or "node_modules/" not in package_path:
            continue
        name = package_path.rsplit("node_modules/", 1)[-1]
        packages.append(
            {
                "integrity": package.get("integrity"),
                "license": package.get("license"),
                "name": name,
                "path": package_path,
                "resolved": package.get("resolved"),
                "version": package.get("version"),
            }
        )
    packages.sort(key=lambda package: package["path"])
    return {
        "packages": packages,
        "schema_version": 1,
        "scope": "VS Code extension development, test, and packaging dependencies",
        "source": "editors/vscode/package-lock.json",
    }


def inventory_text(inventory):
    return json.dumps(inventory, indent=2, sort_keys=True) + "\n"


def check_inventory(path, expected, failures):
    try:
        actual = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        failures.append(f"could not read {path.relative_to(ROOT)}: {error}")
        return
    if actual != inventory_text(expected):
        failures.append(
            f"stale dependency inventory: {path.relative_to(ROOT)} "
            "(run scripts/check-licenses.py --generate)"
        )


def validate_npm_package_sources(packages, failures):
    for package in packages:
        name = package["name"] or "<unknown>"
        version = package["version"] or "<unknown>"
        integrity = package["integrity"]
        resolved = package["resolved"]
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            failures.append(f"missing npm SHA-512 integrity: {name} {version}")
        if not isinstance(resolved, str) or not resolved.startswith(
            "https://registry.npmjs.org/"
        ):
            failures.append(f"untrusted npm resolved URL: {name} {version}")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--generate",
        action="store_true",
        help="rewrite deterministic Cargo and npm dependency inventories",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    failures = []
    for relative, expected_digest in ROOT_LICENSES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"missing reviewed license file: {relative}")
            continue
        try:
            actual_digest = normalized_digest(path)
        except (OSError, UnicodeError) as error:
            failures.append(f"could not read {relative}: {error}")
            continue
        if actual_digest != expected_digest:
            failures.append(f"license file changed without review: {relative}")

    try:
        metadata = load_metadata()
        packages = metadata["packages"]
    except LicenseCheckError as error:
        failures.append(str(error))
        metadata = None
        packages = None

    try:
        cargo_lock = load_cargo_lock()
    except LicenseCheckError as error:
        failures.append(str(error))
        cargo_lock = None

    try:
        npm_lock = load_npm_lock()
    except LicenseCheckError as error:
        failures.append(str(error))
        npm_lock = None
    if npm_lock is not None and npm_lock["packages"].get("", {}).get("dependencies"):
        failures.append(
            "VS Code extension gained runtime npm dependencies; update its bundled notices "
            "and third-party license policy"
        )

    cargo_inventory_data = (
        cargo_inventory(metadata, cargo_lock)
        if metadata is not None and cargo_lock is not None
        else None
    )
    npm_inventory_data = npm_inventory(npm_lock) if npm_lock is not None else None
    if args.generate and cargo_inventory_data is not None and npm_inventory_data is not None:
        CARGO_INVENTORY.parent.mkdir(parents=True, exist_ok=True)
        CARGO_INVENTORY.write_text(inventory_text(cargo_inventory_data), encoding="utf-8")
        NPM_INVENTORY.write_text(inventory_text(npm_inventory_data), encoding="utf-8")
    if cargo_inventory_data is not None:
        check_inventory(CARGO_INVENTORY, cargo_inventory_data, failures)
    if npm_inventory_data is not None:
        check_inventory(NPM_INVENTORY, npm_inventory_data, failures)

    seen_expressions = set()
    if packages is not None:
        for package in packages:
            name = package.get("name", "<unknown>")
            version = package.get("version", "<unknown>")
            expression = package.get("license")
            if not isinstance(expression, str) or not expression.strip():
                failures.append(f"missing license expression: {name} {version}")
                continue
            seen_expressions.add(expression)
            if expression not in REVIEWED_LICENSE_EXPRESSIONS:
                failures.append(
                    f"unreviewed license expression: {name} {version}: {expression}"
                )

        unused_expressions = REVIEWED_LICENSE_EXPRESSIONS - seen_expressions
        for expression in sorted(unused_expressions):
            failures.append(f"reviewed expression is no longer in Cargo.lock: {expression}")

    npm_expressions = set()
    npm_packages = npm_inventory_data["packages"] if npm_inventory_data is not None else None
    if npm_packages is not None:
        validate_npm_package_sources(npm_packages, failures)
        for package in npm_packages:
            name = package["name"] or "<unknown>"
            version = package["version"] or "<unknown>"
            expression = package["license"]
            if not isinstance(expression, str) or not expression.strip():
                failures.append(f"missing npm license expression: {name} {version}")
                continue
            npm_expressions.add(expression)
            if expression not in NPM_REVIEWED_LICENSE_EXPRESSIONS:
                failures.append(
                    f"unreviewed npm license expression: {name} {version}: {expression}"
                )
            if expression == "SEE LICENSE IN LICENSE.txt" and not name.startswith(
                "@vscode/vsce-sign"
            ):
                failures.append(
                    f"unreviewed npm custom license file: {name} {version}"
                )

        unused_npm_expressions = NPM_REVIEWED_LICENSE_EXPRESSIONS - npm_expressions
        for expression in sorted(unused_npm_expressions):
            failures.append(
                f"reviewed npm expression is no longer in package-lock.json: {expression}"
            )

    if failures:
        print("License check failed:", file=sys.stderr)
        for failure in sorted(failures):
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "License check passed: "
        f"{len((cargo_inventory_data or {}).get('packages', []))} Cargo dependencies, "
        f"{len(seen_expressions)} reviewed expressions, "
        f"{len(npm_packages or [])} npm development packages, "
        f"{len(npm_expressions)} reviewed npm expressions, "
        f"{len(ROOT_LICENSES)} reviewed license files"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
