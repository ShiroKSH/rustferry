#!/usr/bin/env python3
"""Extract one release section from CHANGELOG.md."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Sequence


SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
REVISION = re.compile(r"^[0-9a-fA-F]{40}$")
H2 = re.compile(r"^##(?:[ \t]+|$)")
UNRELEASED_MARKER = "No public release has been cut."


class ReleaseNotesError(ValueError):
    pass


def _version_heading(version: str) -> re.Pattern[str]:
    escaped = re.escape(version)
    return re.compile(
        rf"^##[ \t]+(?:\[v?{escaped}\]|v?{escaped})"
        r"(?:[ \t]+-[ \t]+[^ \t\r\n][^\r\n]*)?[ \t]*$"
    )


def _targets_version(line: str, version: str) -> bool:
    if H2.match(line) is None:
        return False
    content = line[2:].strip()
    if not content:
        return False
    token = content.split(maxsplit=1)[0]
    return token.strip("[]") in {version, f"v{version}"}


def extract_release_notes(changelog: str, version: str) -> str:
    if SEMVER.fullmatch(version) is None:
        raise ReleaseNotesError(f"invalid semantic version: {version}")

    heading = _version_heading(version)
    lines = changelog.splitlines()
    matches: list[int] = []
    for index, line in enumerate(lines):
        if heading.fullmatch(line) is not None:
            matches.append(index)
        elif _targets_version(line, version):
            raise ReleaseNotesError(f"malformed release heading for {version}")

    if not matches:
        raise ReleaseNotesError(f"changelog has no release heading for {version}")
    if len(matches) != 1:
        raise ReleaseNotesError(f"changelog has duplicate release headings for {version}")

    start = matches[0] + 1
    end = next(
        (index for index in range(start, len(lines)) if H2.match(lines[index])),
        len(lines),
    )
    body_lines = lines[start:end]
    while body_lines and not body_lines[0].strip():
        body_lines.pop(0)
    while body_lines and not body_lines[-1].strip():
        body_lines.pop()

    if not body_lines:
        raise ReleaseNotesError(f"release notes for {version} are empty")
    body = "\n".join(body_lines)
    if UNRELEASED_MARKER in body:
        raise ReleaseNotesError(f"release notes for {version} still mark the release as unreleased")
    return body


def _write_atomic(output: Path, content: str) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(content)
        os.replace(temporary_path, output)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--changelog", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    if REVISION.fullmatch(args.revision) is None:
        print("release notes extraction failed: revision must be a 40-character SHA", file=sys.stderr)
        return 1

    try:
        changelog = args.changelog.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        print("release notes extraction failed: could not read changelog", file=sys.stderr)
        return 1

    try:
        body = extract_release_notes(changelog, args.version)
        notes = (
            f"# RustFerry {args.version}\n\n"
            f"Revision: `{args.revision}`\n\n"
            f"{body}\n"
        )
        _write_atomic(args.output, notes)
    except ReleaseNotesError as error:
        print(f"release notes extraction failed: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("release notes extraction failed: could not write output", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
