from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "require-release-checks.py"
SPEC = importlib.util.spec_from_file_location("require_release_checks", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class RequireReleaseChecksTests(unittest.TestCase):
    REVISION = "a" * 40

    def run_document(self, **overrides):
        run = {
            "id": 7,
            "head_sha": self.REVISION,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "run_number": 4,
            "run_attempt": 1,
        }
        run.update(overrides)
        return {"workflow_runs": [run]}

    def test_accepts_successful_exact_sha_push(self) -> None:
        run = MODULE.select_exact_push_run(
            self.run_document(), self.REVISION, "ci.yml"
        )
        self.assertEqual(run["id"], 7)

    def test_rejects_pull_request_run_for_exact_sha(self) -> None:
        with self.assertRaises(MODULE.CheckError):
            MODULE.select_exact_push_run(
                self.run_document(event="pull_request"), self.REVISION, "ci.yml"
            )

    def test_latest_attempt_must_be_green(self) -> None:
        document = self.run_document()
        document["workflow_runs"].append(
            {
                "id": 8,
                "head_sha": self.REVISION,
                "event": "push",
                "status": "completed",
                "conclusion": "failure",
                "run_number": 4,
                "run_attempt": 2,
            }
        )
        with self.assertRaises(MODULE.CheckError):
            MODULE.select_exact_push_run(document, self.REVISION, "ci.yml")

    def test_required_job_must_be_unique_and_green(self) -> None:
        MODULE.require_jobs(
            {
                "total_count": 1,
                "jobs": [
                    {"name": "required", "status": "completed", "conclusion": "success"}
                ],
            },
            {"required"},
            "ci.yml",
        )
        with self.assertRaises(MODULE.CheckError):
            MODULE.require_jobs(
                {
                    "total_count": 1,
                    "jobs": [
                        {
                            "name": "required",
                            "status": "completed",
                            "conclusion": "skipped",
                        }
                    ],
                },
                {"required"},
                "ci.yml",
            )

    def test_release_tag_must_point_directly_to_exact_revision(self) -> None:
        document = {
            "ref": "refs/tags/v1.2.3",
            "object_sha": self.REVISION,
            "object_type": "commit",
        }
        MODULE.validate_tag_ref(document, "v1.2.3", self.REVISION)
        with self.assertRaisesRegex(MODULE.CheckError, "exact revision"):
            MODULE.validate_tag_ref(
                {**document, "object_sha": "b" * 40}, "v1.2.3", self.REVISION
            )
        with self.assertRaisesRegex(MODULE.CheckError, "directly to a commit"):
            MODULE.validate_tag_ref(
                {**document, "object_type": "tag"}, "v1.2.3", self.REVISION
            )

    def test_tag_creation_uses_atomic_create_ref_api(self) -> None:
        response = {
            "ref": "refs/tags/v1.2.3",
            "object_sha": self.REVISION,
            "object_type": "commit",
        }
        with patch.object(MODULE, "gh_api_object", return_value=response) as api:
            MODULE.create_tag_ref("owner/repository", "v1.2.3", self.REVISION)
        api.assert_called_once_with(
            "repos/owner/repository/git/refs",
            {"ref": "refs/tags/v1.2.3", "sha": self.REVISION},
            MODULE.TAG_REF_PROJECTION,
            method="POST",
        )

    def test_draft_workflow_atomically_binds_and_verifies_tag(self) -> None:
        workflow = (ROOT / ".github/workflows/draft-release.yml").read_text(
            encoding="utf-8"
        )
        create = workflow.index('gh release create "$tag"')
        tag_assignment = workflow.rindex('tag="v$RELEASE_VERSION"', 0, create)
        release_lookup = workflow.index('gh release view "$tag"', tag_assignment, create)
        bind = workflow.index('--create-tag "$tag"', release_lookup, create)
        verify = workflow.index('--verify-tag "$tag"', create)
        self.assertLess(tag_assignment, release_lookup)
        self.assertLess(release_lookup, bind)
        self.assertLess(bind, create)
        self.assertLess(create, verify)
        release_command = workflow[create:verify]
        self.assertIn("--verify-tag", release_command)
        self.assertNotIn("--target", release_command)
        self.assertIn("retained refs/tags/$tag", release_command)
        self.assertNotIn("git tag ", workflow)


if __name__ == "__main__":
    unittest.main()
