#!/usr/bin/env python3
"""Require successful push workflow jobs for the exact release revision."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any
from urllib.parse import quote


REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REVISION = re.compile(r"^[0-9a-fA-F]{40}$")
TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
API_TIMEOUT_SECONDS = 30
MAX_OUTPUT_BYTES = 256 * 1024
REQUIRED_WORKFLOWS = {
    "ci.yml": {
        "Linux quality and docs",
        "Rust 1.92 minimum version",
        "Tests and templates (ubuntu-latest)",
        "Tests and templates (macos-latest)",
        "Tests and templates (windows-latest)",
    },
    "vscode-extension.yml": {
        "Extension checks (ubuntu-latest)",
        "Extension checks (macos-latest)",
        "Extension checks (windows-latest)",
    },
    "platform-artifacts.yml": {
        "Signed Android APK",
        "iOS app and extensions",
    },
    "docs.yml": {"Build mdBook", "Deploy GitHub Pages"},
}


class CheckError(RuntimeError):
    pass


def gh_api(
    endpoint: str, fields: dict[str, str], jq: str, *, method: str = "GET"
) -> Any:
    command = ["gh", "api", "--method", method, endpoint]
    for key, value in fields.items():
        command.extend(("-f", f"{key}={value}"))
    command.extend(("--jq", jq))
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as error:
        raise CheckError("GitHub CLI executable was not found") from error
    try:
        stdout, stderr = process.communicate(timeout=API_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate()
        raise CheckError(f"GitHub API request timed out: {endpoint}") from error
    if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
        raise CheckError(f"GitHub API response exceeded the output limit: {endpoint}")
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()[:4096]
        raise CheckError(f"GitHub API request failed for {endpoint}: {detail}")
    try:
        result = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CheckError(f"GitHub API returned invalid JSON for {endpoint}") from error
    return result


def gh_api_object(
    endpoint: str, fields: dict[str, str], jq: str, *, method: str = "GET"
) -> dict[str, Any]:
    result = gh_api(endpoint, fields, jq, method=method)
    if not isinstance(result, dict):
        raise CheckError(f"GitHub API returned an unexpected document for {endpoint}")
    return result


def select_exact_push_run(document: dict[str, Any], revision: str, workflow: str) -> dict[str, Any]:
    runs = document.get("workflow_runs")
    if not isinstance(runs, list) or not runs:
        raise CheckError(f"{workflow} has no push run for exact revision {revision}")
    exact = [
        run
        for run in runs
        if run.get("head_sha", "").lower() == revision.lower() and run.get("event") == "push"
    ]
    if not exact:
        raise CheckError(f"{workflow} has no exact-SHA push run for {revision}")
    run = max(
        exact,
        key=lambda item: (
            int(item.get("run_number", 0)),
            int(item.get("run_attempt", 0)),
            int(item.get("id", 0)),
        ),
    )
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise CheckError(
            f"{workflow} exact-SHA push run is {run.get('status')}/{run.get('conclusion')}: "
            f"{run.get('html_url', '<no URL>')}"
        )
    return run


def require_jobs(document: dict[str, Any], required: set[str], workflow: str) -> None:
    if int(document.get("total_count", 0)) > 100:
        raise CheckError(f"{workflow} produced more than 100 jobs; pagination is not allowed")
    jobs = document.get("jobs")
    if not isinstance(jobs, list):
        raise CheckError(f"{workflow} jobs response is malformed")
    by_name: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        name = job.get("name")
        if isinstance(name, str):
            by_name.setdefault(name, []).append(job)
    for name in sorted(required):
        matches = by_name.get(name, [])
        if len(matches) != 1:
            raise CheckError(f"{workflow} expected one {name!r} job, found {len(matches)}")
        job = matches[0]
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            raise CheckError(
                f"{workflow} job {name!r} is {job.get('status')}/{job.get('conclusion')}: "
                f"{job.get('html_url', '<no URL>')}"
            )


def validate_tag_ref(document: dict[str, Any], tag: str, revision: str) -> None:
    exact_ref = f"refs/tags/{tag}"
    if document.get("ref") != exact_ref:
        raise CheckError(f"GitHub returned the wrong release ref for {tag}")
    if document.get("object_type") != "commit":
        raise CheckError(f"release tag {exact_ref} does not point directly to a commit")
    object_sha = document.get("object_sha")
    if not isinstance(object_sha, str) or object_sha.lower() != revision.lower():
        raise CheckError(
            f"release tag {exact_ref} does not point to exact revision {revision}"
        )


TAG_REF_PROJECTION = "{ref, object_sha: .object.sha, object_type: .object.type}"


def create_tag_ref(repository: str, tag: str, revision: str) -> None:
    document = gh_api_object(
        f"repos/{repository}/git/refs",
        {"ref": f"refs/tags/{tag}", "sha": revision},
        TAG_REF_PROJECTION,
        method="POST",
    )
    validate_tag_ref(document, tag, revision)


def verify_tag_ref(repository: str, tag: str, revision: str) -> None:
    document = gh_api_object(
        f"repos/{repository}/git/ref/tags/{quote(tag, safe='')}",
        {},
        TAG_REF_PROJECTION,
    )
    validate_tag_ref(document, tag, revision)


def verify(repository: str, revision: str) -> None:
    run_filter = {
        "event": "push",
        "head_sha": revision,
        "per_page": "100",
    }
    run_projection = (
        "{workflow_runs: [.workflow_runs[] | "
        "{id, head_sha, event, status, conclusion, run_number, run_attempt, html_url}]}"
    )
    job_projection = (
        "{total_count, jobs: [.jobs[] | {name, status, conclusion, html_url}]}"
    )
    for workflow, required_jobs in REQUIRED_WORKFLOWS.items():
        runs = gh_api_object(
            f"repos/{repository}/actions/workflows/{workflow}/runs",
            run_filter,
            run_projection,
        )
        run = select_exact_push_run(runs, revision, workflow)
        jobs = gh_api_object(
            f"repos/{repository}/actions/runs/{run['id']}/jobs",
            {"filter": "latest", "per_page": "100"},
            job_projection,
        )
        require_jobs(jobs, required_jobs, workflow)
        print(f"{workflow}: {run.get('html_url', run['id'])}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--create-tag")
    operation.add_argument("--verify-tag")
    args = parser.parse_args()
    if not REPOSITORY.fullmatch(args.repository):
        parser.error("--repository must be OWNER/REPO")
    if not REVISION.fullmatch(args.sha):
        parser.error("--sha must be a full 40-character Git revision")
    revision = args.sha.lower()
    try:
        if args.create_tag is not None:
            if not TAG.fullmatch(args.create_tag):
                parser.error("--create-tag must be vVERSION")
            create_tag_ref(args.repository, args.create_tag, revision)
            print(f"release tag created at {revision}: refs/tags/{args.create_tag}")
        elif args.verify_tag is not None:
            if not TAG.fullmatch(args.verify_tag):
                parser.error("--verify-tag must be vVERSION")
            verify_tag_ref(args.repository, args.verify_tag, revision)
            print(f"release tag verified at {revision}: refs/tags/{args.verify_tag}")
        else:
            verify(args.repository, revision)
            print(f"all required checks passed for {revision}")
    except CheckError as error:
        print(f"release check gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
