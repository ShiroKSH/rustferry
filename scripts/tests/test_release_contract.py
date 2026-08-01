from __future__ import annotations

import importlib.util
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
