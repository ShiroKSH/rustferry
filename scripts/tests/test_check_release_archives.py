from contextlib import contextmanager
import importlib.util
from io import BytesIO
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-release-archives.py"
SPEC = importlib.util.spec_from_file_location("check_release_archives", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ReleaseArchiveTests(unittest.TestCase):
    def test_crates_io_compressed_size_limit_is_ten_mebibytes(self):
        self.assertEqual(CHECKER.MAX_ARCHIVE_BYTES, 10 * 1024 * 1024)

    def test_source_workspace_uses_only_extracted_package_paths(self):
        workspace = Path("/temporary/package-sources")
        manifest = CHECKER.source_workspace_manifest(
            {
                "cargo-ferry": workspace / "cargo-ferry-0.1.0",
                "rustferry-core": workspace / "rustferry-core-0.1.0",
            },
            workspace,
        )
        self.assertIn('members = ["cargo-ferry-0.1.0", "rustferry-core-0.1.0"]', manifest)
        self.assertIn('"rustferry-core" = { path = "rustferry-core-0.1.0" }', manifest)
        self.assertNotIn("/temporary", manifest)

    def test_packaged_handshake_requires_registry_runtime_readiness(self):
        source = '{"runtime_dependency":{"source":"registry","usable":true}}'
        self.assertEqual(CHECKER.validate_packaged_handshake(source), [])

        failure = CHECKER.validate_packaged_handshake(
            '{"runtime_dependency":{"source":"registry","usable":false}}'
        )
        self.assertEqual(len(failure), 1)

    def test_packaged_handshake_rejects_invalid_json(self):
        failure = CHECKER.validate_packaged_handshake("not-json")
        self.assertEqual(len(failure), 1)
        self.assertIn("invalid JSON", failure[0])

    def test_safe_unknown_binary_member_is_allowed(self):
        with self.archive(b"\x00\xffsafe binary payload") as archive:
            self.assertEqual(CHECKER.check_archive(archive), [])

    def test_secret_in_unknown_binary_member_is_rejected(self):
        token = b"gh" + b"p_" + (b"A" * 20)
        with self.archive(b"\x00" + token + b"\xff") as archive:
            failures = CHECKER.check_archive(archive)
        self.assertIn(
            "private material in member: fixture-0.1.0/assets/payload.dat",
            failures,
        )

    def test_secret_split_across_scan_chunks_is_rejected(self):
        token = b"gh" + b"p_" + (b"B" * 20)
        payload = (b"x" * (CHECKER.SCAN_CHUNK_BYTES - 3)) + b"\x00" + token
        with self.archive(payload) as archive:
            failures = CHECKER.check_archive(archive)
        self.assertIn(
            "private material in member: fixture-0.1.0/assets/payload.dat",
            failures,
        )

    @contextmanager
    def archive(self, payload):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "fixture.crate"
            with tarfile.open(archive, mode="w:gz") as package:
                self.add_file(
                    package,
                    "fixture-0.1.0/Cargo.toml",
                    b"[package]\nname='fixture'\nversion='0.1.0'\n",
                )
                for license_name in CHECKER.REQUIRED_LICENSES:
                    self.add_file(
                        package,
                        f"fixture-0.1.0/{license_name}",
                        (ROOT / license_name).read_bytes(),
                    )
                self.add_file(package, "fixture-0.1.0/assets/payload.dat", payload)
            yield archive

    @staticmethod
    def add_file(package, name, contents):
        member = tarfile.TarInfo(name)
        member.mode = 0o644
        member.size = len(contents)
        package.addfile(member, BytesIO(contents))


if __name__ == "__main__":
    unittest.main()
