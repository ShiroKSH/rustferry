from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-release-contract.py"
SPEC = importlib.util.spec_from_file_location("check_release_contract", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ReleaseContractTests(unittest.TestCase):
    def test_repository_contract(self) -> None:
        failures, checked_edges = MODULE.validate(ROOT, "0.1.0")
        self.assertEqual(failures, [])
        self.assertGreater(checked_edges, 0)

    def test_invalid_semver_fails_without_reading_the_repository(self) -> None:
        failures, checked_edges = MODULE.validate(ROOT, "release-next")
        self.assertEqual(failures, ["invalid semantic version: release-next"])
        self.assertEqual(checked_edges, 0)

    def test_dependency_identity_honors_package_aliases(self) -> None:
        self.assertEqual(
            MODULE.dependency_identity(
                "runtime-contract",
                {"package": "rustferry", "version": "=1.2.3"},
            ),
            ("rustferry", "=1.2.3", False),
        )

    def test_manifest_discovery_ignores_goal3_scratch_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tracked = root / "crates" / "example" / "Cargo.toml"
            scratch = root / ".goal3" / "tmp" / "probe" / "Cargo.toml"
            tracked.parent.mkdir(parents=True)
            scratch.parent.mkdir(parents=True)
            tracked.write_text("[package]\nname = 'example'\n", encoding="utf-8")
            scratch.write_text("not valid TOML", encoding="utf-8")

            self.assertEqual(MODULE.manifest_paths(root), [tracked])


if __name__ == "__main__":
    unittest.main()
