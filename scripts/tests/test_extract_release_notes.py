from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "extract_release_notes.py"
SPEC = importlib.util.spec_from_file_location("extract_release_notes", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ExtractReleaseNotesTests(unittest.TestCase):
    def test_bracketed_heading_with_date(self) -> None:
        changelog = "## [0.1.0] - 2026-08-12\n\nRelease body.\n"
        self.assertEqual(MODULE.extract_release_notes(changelog, "0.1.0"), "Release body.")

    def test_supported_heading_forms(self) -> None:
        for heading in ("## 0.1.0", "## v0.1.0", "## [v0.1.0]"):
            with self.subTest(heading=heading):
                self.assertEqual(
                    MODULE.extract_release_notes(f"{heading}\n\nRelease body.\n", "0.1.0"),
                    "Release body.",
                )

    def test_crlf_input(self) -> None:
        changelog = "## [0.1.0] - 2026-08-12\r\n\r\nFirst.\r\n\r\nSecond.\r\n"
        self.assertEqual(
            MODULE.extract_release_notes(changelog, "0.1.0"),
            "First.\n\nSecond.",
        )

    def test_stops_before_next_h2(self) -> None:
        changelog = "## 0.1.0\n\nRelease body.\n\n## 0.0.9\n\nOlder body.\n"
        self.assertEqual(MODULE.extract_release_notes(changelog, "0.1.0"), "Release body.")

    def test_missing_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.ReleaseNotesError, "no release heading"):
            MODULE.extract_release_notes("## 0.0.9\n\nOlder body.\n", "0.1.0")

    def test_empty_section_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.ReleaseNotesError, "are empty"):
            MODULE.extract_release_notes("## 0.1.0\n\n## 0.0.9\nOlder body.\n", "0.1.0")

    def test_duplicate_version_is_rejected(self) -> None:
        changelog = "## 0.1.0\nFirst.\n## [0.1.0]\nSecond.\n"
        with self.assertRaisesRegex(MODULE.ReleaseNotesError, "duplicate release headings"):
            MODULE.extract_release_notes(changelog, "0.1.0")

    def test_unreleased_marker_is_rejected(self) -> None:
        changelog = "## 0.1.0\n\nNo public release has been cut.\n"
        with self.assertRaisesRegex(MODULE.ReleaseNotesError, "mark the release as unreleased"):
            MODULE.extract_release_notes(changelog, "0.1.0")

    def test_unmatched_brackets_are_rejected(self) -> None:
        for heading in ("## [0.1.0", "## 0.1.0]"):
            with self.subTest(heading=heading):
                with self.assertRaisesRegex(MODULE.ReleaseNotesError, "malformed release heading"):
                    MODULE.extract_release_notes(f"{heading}\n\nRelease body.\n", "0.1.0")

    def test_repository_changelog(self) -> None:
        body = MODULE.extract_release_notes(
            (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
            "0.1.0",
        )
        self.assertTrue(body)
        self.assertIn("RustFerry 0.1.0 is a public pre-release.", body)
        self.assertIn("- Establish the RustFerry workspace", body)
        self.assertNotIn("## Unreleased", body)
        self.assertNotIn("\n## ", body)

    def test_cli_writes_complete_release_notes(self) -> None:
        revision = "d15f9d01918ba3470bb17622998d3a68016ac3bc"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "RELEASE_NOTES.md"
            process = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--changelog",
                    str(ROOT / "CHANGELOG.md"),
                    "--version",
                    "0.1.0",
                    "--revision",
                    revision,
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            notes = output.read_text(encoding="utf-8")
            self.assertTrue(notes.startswith("# RustFerry 0.1.0\n\n"))
            self.assertIn(f"Revision: `{revision}`", notes)
            self.assertIn("RustFerry 0.1.0 is a public pre-release.", notes)
            self.assertTrue(notes.endswith("\n"))
            self.assertFalse(notes.endswith("\n\n"))

    def test_cli_failure_leaves_no_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changelog = root / "CHANGELOG.md"
            output = root / "RELEASE_NOTES.md"
            changelog.write_text("## 0.0.9\n\nOlder body.\n", encoding="utf-8")
            process = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--changelog",
                    str(changelog),
                    "--version",
                    "0.1.0",
                    "--revision",
                    "d15f9d01918ba3470bb17622998d3a68016ac3bc",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse(output.exists())
            self.assertNotIn("Older body", process.stderr)


if __name__ == "__main__":
    unittest.main()
