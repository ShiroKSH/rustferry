from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-vscode-marketplace.yml"


class MarketplaceWorkflowTests(unittest.TestCase):
    def test_publication_is_manual_protected_and_assembly_bound(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("name: vscode-marketplace", workflow)
        self.assertIn("run-id: ${{ inputs.assembly_run_id }}", workflow)
        self.assertIn(".head_sha == $sha", workflow)
        self.assertIn(".workflow_id == $workflow_id", workflow)
        self.assertIn("shasum -a 256 -c SHA256SUMS", workflow)

    def test_pat_is_only_mapped_to_the_publish_step(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow.count("secrets.VSCE_PAT"), 1)
        self.assertIn("VSCE_PAT: ${{ secrets.VSCE_PAT }}", workflow)
        self.assertIn("npx --no-install vsce publish", workflow)
        self.assertIn("--pre-release", workflow)
        self.assertIn("--packagePath", workflow)
        self.assertNotIn("--pat", workflow)


if __name__ == "__main__":
    unittest.main()
