#!/usr/bin/env python3
"""Run and verify the protected CI check on an exact release candidate commit."""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any


CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
REQUIRED_CHECK_NAME = "Required checks"
MAX_WAIT_SECONDS = 45 * 60
POLL_INTERVAL_SECONDS = 20


class CandidateCiError(RuntimeError):
    """The release candidate did not receive the required successful CI check."""


class GitHubApi:
    def __init__(self, token: str, repository: str):
        owner, separator, repo = repository.partition("/")
        if not separator or not owner or not repo or "/" in repo:
            raise CandidateCiError("GITHUB_REPOSITORY must be owner/repository")
        self.token = token
        self.repository_path = (
            f"/repos/{urllib.parse.quote(owner, safe='')}/"
            f"{urllib.parse.quote(repo, safe='')}"
        )

    def request(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"https://api.github.com{self.repository_path}{path}",
            data=data,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
            method="POST" if data is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            raise CandidateCiError(
                f"GitHub Actions API returned HTTP {error.code}"
            ) from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            raise CandidateCiError("GitHub Actions API request failed") from None

    def list_ci_runs(self, candidate_sha: str, candidate_branch: str) -> list[Any]:
        query = urllib.parse.urlencode(
            {
                "head_sha": candidate_sha,
                "branch": candidate_branch,
                "event": "push",
                "per_page": 100,
            }
        )
        response = self.request(f"/actions/runs?{query}")
        runs = response.get("workflow_runs") if isinstance(response, dict) else None
        if not isinstance(runs, list):
            raise CandidateCiError("GitHub API returned an invalid workflow-runs list")
        return runs

    def get_run(self, run_id: int) -> dict[str, Any]:
        response = self.request(f"/actions/runs/{run_id}")
        if not isinstance(response, dict):
            raise CandidateCiError("GitHub API returned an invalid workflow run")
        return response

    def get_jobs(self, run_id: int) -> list[Any]:
        response = self.request(f"/actions/runs/{run_id}/jobs?per_page=100")
        jobs = response.get("jobs") if isinstance(response, dict) else None
        if not isinstance(jobs, list):
            raise CandidateCiError("GitHub API returned an invalid workflow-jobs list")
        if response.get("total_count") != len(jobs):
            raise CandidateCiError("GitHub returned an incomplete workflow-jobs list")
        return jobs


def is_candidate_ci_run(
    run: Any,
    candidate_sha: str,
    candidate_branch: str,
) -> bool:
    return (
        isinstance(run, dict)
        and run.get("name") == "CI"
        and run.get("path") == CI_WORKFLOW_PATH
        and run.get("event") == "push"
        and run.get("head_sha") == candidate_sha
        and run.get("head_branch") == candidate_branch
    )


def wait_for_candidate_ci(
    api: GitHubApi,
    candidate_branch: str,
    candidate_sha: str,
    *,
    timeout_seconds: float = MAX_WAIT_SECONDS,
    poll_interval_seconds: float = POLL_INTERVAL_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    if not candidate_branch.startswith("release-candidate-"):
        raise CandidateCiError("refusing to wait outside a release-candidate branch")
    if not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
        raise CandidateCiError("candidate SHA must be a full lowercase Git commit SHA")
    if timeout_seconds <= 0 or poll_interval_seconds <= 0:
        raise ValueError("CI wait timeout and polling interval must be positive")

    deadline = monotonic() + timeout_seconds
    run_id: int | None = None
    last_status: str | None = None
    print(f"Waiting for push-triggered CI on release candidate {candidate_sha}.")

    while True:
        if run_id is None:
            matching_runs = [
                run
                for run in api.list_ci_runs(candidate_sha, candidate_branch)
                if is_candidate_ci_run(run, candidate_sha, candidate_branch)
            ]
            if len(matching_runs) > 1:
                raise CandidateCiError(
                    "multiple CI workflow runs match the release candidate"
                )
            if matching_runs:
                raw_run_id = matching_runs[0].get("id")
                if not isinstance(raw_run_id, int) or isinstance(raw_run_id, bool):
                    raise CandidateCiError("matching CI run has an invalid ID")
                run_id = raw_run_id

        if run_id is not None:
            run = api.get_run(run_id)
            if not is_candidate_ci_run(run, candidate_sha, candidate_branch):
                raise CandidateCiError("CI run identity does not match the release candidate")
            status = run.get("status")
            if status != last_status:
                print(f"Candidate CI run {run_id}: {status}.")
                last_status = status if isinstance(status, str) else None

            if status == "completed":
                if run.get("conclusion") != "success":
                    raise CandidateCiError(
                        f"candidate CI run {run_id} concluded "
                        f"{run.get('conclusion') or 'without a conclusion'}"
                    )
                attempt = run.get("run_attempt", 1)
                if not isinstance(attempt, int) or isinstance(attempt, bool):
                    raise CandidateCiError("candidate CI run has an invalid attempt number")
                required_jobs = [
                    job
                    for job in api.get_jobs(run_id)
                    if isinstance(job, dict)
                    and job.get("name") == REQUIRED_CHECK_NAME
                    and job.get("run_attempt", attempt) == attempt
                ]
                if len(required_jobs) != 1:
                    raise CandidateCiError(
                        f"candidate CI run {run_id} has no unique "
                        f"{REQUIRED_CHECK_NAME} job for attempt {attempt}"
                    )
                required_job = required_jobs[0]
                if (
                    required_job.get("status") != "completed"
                    or required_job.get("conclusion") != "success"
                ):
                    raise CandidateCiError(
                        f"candidate CI run {run_id} did not pass {REQUIRED_CHECK_NAME}"
                    )
                print(
                    f"{REQUIRED_CHECK_NAME} passed on candidate SHA {candidate_sha}."
                )
                return run_id

            if status not in {
                "queued",
                "in_progress",
                "waiting",
                "requested",
                "pending",
            }:
                raise CandidateCiError(f"candidate CI run has unexpected status {status!r}")

        remaining = deadline - monotonic()
        if remaining <= 0:
            detail = f"CI run {run_id}" if run_id is not None else "CI run"
            raise CandidateCiError(
                f"timed out waiting for {detail} on candidate SHA {candidate_sha}"
            )
        sleep(min(poll_interval_seconds, remaining))


def self_test() -> None:
    candidate_branch = "release-candidate-v26.10.26-12345-1"
    candidate_sha = "a" * 40

    def workflow_run(
        *,
        run_id: int = 123,
        status: str = "completed",
        conclusion: str = "success",
        sha: str = candidate_sha,
        event: str = "push",
    ) -> dict[str, Any]:
        return {
            "id": run_id,
            "name": "CI",
            "path": CI_WORKFLOW_PATH,
            "event": event,
            "head_sha": sha,
            "head_branch": candidate_branch,
            "run_attempt": 1,
            "status": status,
            "conclusion": conclusion,
        }

    required_job = {
        "name": REQUIRED_CHECK_NAME,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
    }

    class ApiStub:
        def __init__(
            self,
            runs: list[list[dict[str, Any]]],
            run: dict[str, Any],
            jobs: list[dict[str, Any]],
        ) -> None:
            self.run_responses = list(runs)
            self.run = run
            self.jobs = jobs
            self.list_calls = 0
            self.job_calls = 0

        def list_ci_runs(self, sha: str, branch: str) -> list[dict[str, Any]]:
            assert sha == candidate_sha
            assert branch == candidate_branch
            self.list_calls += 1
            return self.run_responses.pop(0) if self.run_responses else []

        def get_run(self, run_id: int) -> dict[str, Any]:
            assert run_id == 123
            return self.run

        def get_jobs(self, run_id: int) -> list[dict[str, Any]]:
            assert run_id == 123
            self.job_calls += 1
            return self.jobs

    delays: list[float] = []
    old_dispatch = workflow_run(event="workflow_dispatch")
    eventual_api = ApiStub(
        [[old_dispatch], [], [workflow_run()]], workflow_run(), [required_job]
    )
    assert wait_for_candidate_ci(
        eventual_api,
        candidate_branch,
        candidate_sha,
        timeout_seconds=10,
        poll_interval_seconds=2,
        sleep=delays.append,
        monotonic=lambda: 0,
    ) == 123
    assert eventual_api.list_calls == 3
    assert eventual_api.job_calls == 1
    assert delays == [2, 2]

    duplicate_runs_api = ApiStub(
        [[workflow_run(run_id=122), workflow_run()]], workflow_run(), [required_job]
    )
    try:
        wait_for_candidate_ci(
            duplicate_runs_api,
            candidate_branch,
            candidate_sha,
            timeout_seconds=10,
            poll_interval_seconds=2,
            sleep=lambda _: None,
            monotonic=lambda: 0,
        )
    except CandidateCiError as error:
        assert "multiple CI workflow runs" in str(error)
    else:
        raise AssertionError("duplicate candidate CI runs were accepted")

    job_without_attempt_metadata = {
        "name": REQUIRED_CHECK_NAME,
        "status": "completed",
        "conclusion": "success",
    }
    api_without_attempt_metadata = ApiStub(
        [[], [workflow_run()]], workflow_run(), [job_without_attempt_metadata]
    )
    assert wait_for_candidate_ci(
        api_without_attempt_metadata,
        candidate_branch,
        candidate_sha,
        timeout_seconds=10,
        poll_interval_seconds=2,
        sleep=lambda _: None,
        monotonic=lambda: 0,
    ) == 123

    failed_api = ApiStub(
        [[], [workflow_run(conclusion="failure")]],
        workflow_run(conclusion="failure"),
        [required_job],
    )
    try:
        wait_for_candidate_ci(
            failed_api,
            candidate_branch,
            candidate_sha,
            timeout_seconds=10,
            poll_interval_seconds=2,
            sleep=lambda _: None,
            monotonic=lambda: 0,
        )
    except CandidateCiError as error:
        assert "concluded failure" in str(error)
    else:
        raise AssertionError("failed CI was accepted")
    assert failed_api.job_calls == 0

    missing_check_api = ApiStub([[], [workflow_run()]], workflow_run(), [])
    try:
        wait_for_candidate_ci(
            missing_check_api,
            candidate_branch,
            candidate_sha,
            timeout_seconds=10,
            poll_interval_seconds=2,
            sleep=lambda _: None,
            monotonic=lambda: 0,
        )
    except CandidateCiError as error:
        assert "no unique Required checks job" in str(error)
    else:
        raise AssertionError("CI run without Required checks was accepted")

    duplicate_check_api = ApiStub(
        [[], [workflow_run()]], workflow_run(), [required_job, required_job]
    )
    try:
        wait_for_candidate_ci(
            duplicate_check_api,
            candidate_branch,
            candidate_sha,
            timeout_seconds=10,
            poll_interval_seconds=2,
            sleep=lambda _: None,
            monotonic=lambda: 0,
        )
    except CandidateCiError as error:
        assert "no unique Required checks job" in str(error)
    else:
        raise AssertionError("duplicate Required checks jobs were accepted")

    wrong_sha_api = ApiStub(
        [[], [workflow_run(sha="b" * 40)]], workflow_run(), []
    )
    clock = 0.0

    def advance_clock(seconds: float) -> None:
        nonlocal clock
        clock += seconds

    try:
        wait_for_candidate_ci(
            wrong_sha_api,
            candidate_branch,
            candidate_sha,
            timeout_seconds=3,
            poll_interval_seconds=2,
            sleep=advance_clock,
            monotonic=lambda: clock,
        )
    except CandidateCiError as error:
        assert "timed out waiting for CI run" in str(error)
    else:
        raise AssertionError("a run for the wrong SHA was accepted")
    assert wrong_sha_api.job_calls == 0

    try:
        wait_for_candidate_ci(
            ApiStub([], workflow_run(), []),
            "master",
            candidate_sha,
            timeout_seconds=10,
            poll_interval_seconds=2,
            sleep=lambda _: None,
            monotonic=lambda: 0,
        )
    except CandidateCiError as error:
        assert "outside a release-candidate branch" in str(error)
    else:
        raise AssertionError("CI check outside a candidate branch was accepted")

    print("Release candidate CI gate self-test passed.")


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if sys.argv[1:]:
        print("Usage: release_candidate_ci.py [--self-test]", file=sys.stderr)
        return 2

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    candidate_branch = os.environ.get("CANDIDATE_BRANCH")
    candidate_sha = os.environ.get("CANDIDATE_SHA")
    if not all((token, repository, candidate_branch, candidate_sha)):
        print(
            "GH_TOKEN, GITHUB_REPOSITORY, CANDIDATE_BRANCH, and CANDIDATE_SHA are required",
            file=sys.stderr,
        )
        return 2

    try:
        api = GitHubApi(token, repository)
        wait_for_candidate_ci(api, candidate_branch, candidate_sha)
    except CandidateCiError as error:
        print(f"Release candidate CI gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
