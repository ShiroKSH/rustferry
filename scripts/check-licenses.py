#!/usr/bin/env python3
"""Check repository license files and locked Cargo package licenses."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys


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
    "LICENSE-APACHE": "53395048c41d220b8e2652e20c3f4749cab8e9ae9af7a8f591755bbba7b7325d",
    "LICENSE-MIT": "8d6e17950f6e01812c6489c0a2dfd7f129650c424e3b0b6986fee8ab67d8e45a",
}
REVIEWED_LICENSE_EXPRESSIONS = frozenset(
    {
        "(MIT OR Apache-2.0) AND Unicode-3.0",
        "0BSD OR MIT OR Apache-2.0",
        "Apache-2.0",
        "Apache-2.0 OR MIT",
        "Apache-2.0 WITH LLVM-exception",
        "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
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


def main():
    failures = []
    for relative, expected_digest in ROOT_LICENSES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"missing root license file: {relative}")
            continue
        try:
            actual_digest = normalized_digest(path)
        except (OSError, UnicodeError) as error:
            failures.append(f"could not read {relative}: {error}")
            continue
        if actual_digest != expected_digest:
            failures.append(f"root license file changed without review: {relative}")

    try:
        packages = load_metadata()["packages"]
    except LicenseCheckError as error:
        failures.append(str(error))
        packages = None

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

    if failures:
        print("License check failed:", file=sys.stderr)
        for failure in sorted(failures):
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "License check passed: "
        f"{len(packages or [])} packages, "
        f"{len(seen_expressions)} reviewed expressions, "
        f"{len(ROOT_LICENSES)} root license files"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
