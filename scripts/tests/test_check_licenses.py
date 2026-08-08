import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_licenses", ROOT / "scripts" / "check-licenses.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CHECKER)


class NpmSupplyChainTests(unittest.TestCase):
    def test_accepts_registry_package_with_sha512_integrity(self):
        failures = []
        CHECKER.validate_npm_package_sources(
            [
                {
                    "name": "example",
                    "version": "1.0.0",
                    "integrity": "sha512-dGVzdA==",
                    "resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                }
            ],
            failures,
        )
        self.assertEqual(failures, [])

    def test_rejects_missing_integrity_and_non_registry_url(self):
        failures = []
        CHECKER.validate_npm_package_sources(
            [
                {
                    "name": "example",
                    "version": "1.0.0",
                    "integrity": None,
                    "resolved": "https://example.invalid/example.tgz",
                }
            ],
            failures,
        )
        self.assertEqual(
            failures,
            [
                "missing npm SHA-512 integrity: example 1.0.0",
                "untrusted npm resolved URL: example 1.0.0",
            ],
        )


if __name__ == "__main__":
    unittest.main()
