#!/usr/bin/env python3
"""Merge Dependabot dependency PRs after CI and branch-protection gates pass."""

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


EXPECTED_CI_JOBS = frozenset(
    {
        "Lint",
        "Test (ubuntu-latest)",
        "Test (windows-latest)",
        "Feature compatibility (default)",
        "Feature compatibility (minimal-vless)",
        "Feature compatibility (minimal-vless-tls)",
        "Feature compatibility (vless-reverse)",
        "Feature compatibility (vless-reverse-tls)",
        "Build (linux-gnu)",
        "Build (linux-musl)",
        "Build (windows-msvc)",
        "Required checks",
    }
)
CI_JOB_READ_ATTEMPTS = 5
CI_JOB_RETRY_DELAY_SECONDS = 2
PROTECTED_PATH_PREFIXES = (
    ".github/",
    "docs/ai-",
    "ref/",
    "vendor/",
    "release",
    "install",
)
PROTECTED_PATHS = frozenset({"AGENTS.md", "LESSONS.md"})
ACTION_REFERENCE_LINE = re.compile(
    r"^(?P<indent>[\t ]*)(?P<sequence>-[\t ]+)?uses:[\t ]+"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_.-]+)*)@"
    r"(?P<sha>[0-9a-fA-F]{40})(?:[\t ]+\#[^\r\n]*)?[\t ]*$"
)


class SkipAutomation(Exception):
    """A policy precondition is not met; CI itself remains successful."""


class GitHubApiError(RuntimeError):
    """A GitHub API request failed without exposing credentials or response data."""


class GitHubApi:
    def __init__(self, token: str):
        self.token = token

    def request(
        self,
        url: str,
        payload: dict[str, Any] | None = None,
        method: str | None = None,
    ) -> tuple[Any, dict[str, str]]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
            method=method or ("POST" if data is not None else "GET"),
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read()
                return (json.loads(body) if body else None, dict(response.headers.items()))
        except urllib.error.HTTPError as error:
            raise GitHubApiError(f"GitHub API returned HTTP {error.code}") from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            raise GitHubApiError("GitHub API request failed") from None

    def get(self, path: str) -> Any:
        value, _ = self.request(f"https://api.github.com{path}")
        return value

    def put(self, path: str, payload: dict[str, Any]) -> Any:
        value, _ = self.request(f"https://api.github.com{path}", payload, method="PUT")
        return value

    def get_all(self, path: str, *, collection_key: str | None = None) -> list[Any]:
        url = f"https://api.github.com{path}"
        values: list[Any] = []
        while url:
            page, headers = self.request(url)
            if collection_key is None:
                if not isinstance(page, list):
                    raise GitHubApiError("GitHub API returned an unexpected list response")
                items = page
            else:
                items = page.get(collection_key) if isinstance(page, dict) else None
                if not isinstance(items, list):
                    raise GitHubApiError(
                        f"GitHub API response did not contain a {collection_key} list"
                    )
            values.extend(items)
            url = next_link(headers.get("Link", ""))
        return values


def next_link(header: str) -> str:
    for item in header.split(","):
        url, _, relation = item.strip().partition(";")
        if relation.strip() == 'rel="next"':
            return url.strip("<>")
    return ""


def required_jobs_passed(jobs: list[dict[str, Any]], attempt: int) -> bool:
    state, _ = required_jobs_status(jobs, attempt)
    return state == "passed"


def required_jobs_status(
    jobs: list[dict[str, Any]],
    attempt: int,
) -> tuple[str, list[str]]:
    current: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for job in jobs:
        if job.get("run_attempt", attempt) != attempt:
            continue
        name = job.get("name")
        if name in EXPECTED_CI_JOBS:
            if name in current:
                duplicates.add(name)
            current[name] = job
    if duplicates:
        return "invalid", sorted(duplicates)

    pending: list[str] = []
    failed: list[str] = []
    for name in EXPECTED_CI_JOBS:
        job = current.get(name)
        if job is None or job.get("status") != "completed":
            pending.append(name)
        elif job.get("conclusion") != "success":
            failed.append(name)
    if failed:
        return "failed", sorted(failed)
    if pending:
        return "pending", sorted(pending)
    return "passed", []


def wait_for_required_jobs(
    fetch_jobs: Callable[[], list[dict[str, Any]]],
    attempt: int,
    *,
    max_attempts: int = CI_JOB_READ_ATTEMPTS,
    retry_delay_seconds: float = CI_JOB_RETRY_DELAY_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[bool, str, list[str]]:
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    state = "pending"
    names: list[str] = []
    for read_number in range(max_attempts):
        state, names = required_jobs_status(fetch_jobs(), attempt)
        if state != "pending":
            return state == "passed", state, names
        if read_number + 1 < max_attempts:
            sleep(retry_delay_seconds)
    return False, state, names


def protection_confirmation_enabled(value: str | None) -> bool:
    return value == "true"


def api_path(repository: str, suffix: str) -> str:
    owner, repo = repository.split("/", 1)
    return f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}{suffix}"


def ci_jobs_for_run(api: GitHubApi, repository: str, run_id: str) -> list[Any]:
    path = api_path(repository, f"/actions/runs/{run_id}/jobs?per_page=100")
    return api.get_all(path, collection_key="jobs")


def merge_pull_request(
    api: GitHubApi,
    repository: str,
    pull_request: dict[str, Any],
    expected_head_sha: str,
) -> None:
    try:
        result = api.put(
            api_path(repository, f"/pulls/{pull_request['number']}/merge"),
            {"sha": expected_head_sha, "merge_method": "squash"},
        )
    except GitHubApiError as error:
        if str(error) in {
            "GitHub API returned HTTP 405",
            "GitHub API returned HTTP 409",
        }:
            raise SkipAutomation(
                "GitHub refused the merge because required checks or head synchronization "
                "are not satisfied"
            ) from None
        raise
    if result.get("merged") is not True:
        raise GitHubApiError("GitHub did not confirm the pull request merge")


def merge_when_ready(
    api: GitHubApi,
    repository: str,
    pull_request: dict[str, Any],
    expected_head_sha: str,
) -> None:
    mergeable_state = pull_request.get("mergeable_state")
    if mergeable_state == "clean":
        merge_pull_request(api, repository, pull_request, expected_head_sha)
        return
    if mergeable_state == "unstable" and pull_request.get("mergeable") is True:
        # Optional failing checks can make a conflict-free PR unstable. GitHub's
        # merge endpoint remains authoritative for required branch protections.
        merge_pull_request(api, repository, pull_request, expected_head_sha)
        return
    raise SkipAutomation("GitHub has not satisfied the PR merge gates yet")


def is_dependabot_pull_request(pull_request: dict[str, Any]) -> bool:
    return (pull_request.get("user") or {}).get("login") == "dependabot[bot]"


def is_same_repository_dependabot_pull_request(
    pull_request: dict[str, Any],
    repository: str,
) -> bool:
    head_repository = pull_request.get("head", {}).get("repo") or {}
    return (
        is_dependabot_pull_request(pull_request)
        and head_repository.get("full_name") == repository
    )


def is_auto_merge_eligible(
    pull_request: dict[str, Any],
    repository: str,
) -> bool:
    return (
        is_same_repository_dependabot_pull_request(pull_request, repository)
        and pull_request.get("state") == "open"
        and pull_request.get("draft") is not True
        and pull_request.get("base", {}).get("ref") == "master"
    )


def auto_merge_scope_allowed(
    files: list[Any],
    expected_file_count: Any,
) -> bool:
    if (
        not files
        or not isinstance(expected_file_count, int)
        or isinstance(expected_file_count, bool)
        or expected_file_count != len(files)
    ):
        return False

    if all(is_cargo_dependency_file(changed_file) for changed_file in files):
        return True

    return action_dependency_scope_allowed(files)


def is_cargo_dependency_file(changed_file: Any) -> bool:
    path = changed_file.get("filename") if isinstance(changed_file, dict) else None
    if not isinstance(path, str):
        return False
    return (
        path not in PROTECTED_PATHS
        and path.rsplit("/", 1)[-1] != "CODEOWNERS"
        and not path.startswith(PROTECTED_PATH_PREFIXES)
        and path.rsplit("/", 1)[-1] in {"Cargo.toml", "Cargo.lock"}
    )


def is_action_dependency_file(path: Any) -> bool:
    if not isinstance(path, str) or any(
        part in {"", ".", ".."} for part in path.split("/")
    ):
        return False
    parts = path.split("/")
    if len(parts) == 3 and parts[:2] == [".github", "workflows"]:
        return parts[-1].endswith((".yml", ".yaml"))
    return (
        len(parts) >= 4
        and parts[:2] == [".github", "actions"]
        and parts[-1] in {"action.yml", "action.yaml"}
    )


def action_dependency_scope_allowed(files: list[Any]) -> bool:
    removed_actions: dict[str, dict[str, int]] = {}
    added_actions: dict[str, dict[str, int]] = {}

    for changed_file in files:
        path = changed_file.get("filename") if isinstance(changed_file, dict) else None
        if (
            not isinstance(changed_file, dict)
            or changed_file.get("status", "modified") != "modified"
            or not is_action_dependency_file(path)
        ):
            return False
        patch = changed_file.get("patch")
        if not isinstance(patch, str):
            return False

        file_removed: dict[str, dict[str, int]] = {}
        file_added: dict[str, dict[str, int]] = {}
        removed_block: list[tuple[str, str, tuple[str, str, bool]]] = []
        added_block: list[tuple[str, str, tuple[str, str, bool]]] = []
        has_change = False

        def finish_change_block() -> bool:
            if len(removed_block) != len(added_block):
                return False
            for removed, added in zip(removed_block, added_block, strict=True):
                if removed[0] != added[0] or removed[2] != added[2]:
                    return False
                if removed[1] == added[1]:
                    return False
            removed_block.clear()
            added_block.clear()
            return True

        for patch_line in patch.splitlines():
            if patch_line.startswith("@@"):
                if not finish_change_block():
                    return False
                continue
            if patch_line.startswith("\\"):
                continue
            if not patch_line or patch_line.startswith(" "):
                if not finish_change_block():
                    return False
                continue
            if patch_line[0] not in "+-":
                return False
            match = ACTION_REFERENCE_LINE.fullmatch(patch_line[1:])
            if match is None:
                return False
            if any(
                part in {".", ".."} for part in match.group("action").split("/")
            ):
                return False
            target = file_added if patch_line[0] == "+" else file_removed
            action = match.group("action").lower()
            sha = match.group("sha").lower()
            by_sha = target.setdefault(action, {})
            by_sha[sha] = by_sha.get(sha, 0) + 1
            structure = (
                action,
                match.group("indent"),
                match.group("sequence") is not None,
            )
            change = (action, sha, structure)
            (added_block if patch_line[0] == "+" else removed_block).append(change)
            has_change = True

        if not finish_change_block():
            return False
        if not has_change or not file_removed or not file_added:
            return False
        if {
            action: sum(shas.values()) for action, shas in file_removed.items()
        } != {
            action: sum(shas.values()) for action, shas in file_added.items()
        }:
            return False
        for action in file_removed:
            if file_removed[action] == file_added[action]:
                return False
            for target, source in (
                (removed_actions, file_removed),
                (added_actions, file_added),
            ):
                destination = target.setdefault(action, {})
                for sha, count in source[action].items():
                    destination[sha] = destination.get(sha, 0) + count

    return (
        bool(removed_actions)
        and removed_actions.keys() == added_actions.keys()
        and all(
            sum(removed_actions[action].values())
            == sum(added_actions[action].values())
            and removed_actions[action] != added_actions[action]
            for action in removed_actions
        )
    )


def should_update_dependabot_branch(
    pull_request: dict[str, Any],
    repository: str,
) -> bool:
    return (
        is_auto_merge_eligible(pull_request, repository)
        and pull_request.get("mergeable_state") == "behind"
    )


def merged_pr_number_from_event(event_name: str, event: dict[str, Any]) -> int:
    if event_name == "pull_request_target":
        event_pr = event.get("pull_request") or {}
        if event.get("action") != "closed" or event_pr.get("merged") is not True:
            raise SkipAutomation("the Dependabot pull request was not merged")
        number = event_pr.get("number")
    elif event_name == "workflow_run":
        workflow_run = event.get("workflow_run") or {}
        if (
            workflow_run.get("name") != "CI"
            or workflow_run.get("path") != ".github/workflows/ci.yml"
            or workflow_run.get("event") != "pull_request"
            or workflow_run.get("conclusion") != "success"
        ):
            raise SkipAutomation("the completed workflow is not a successful PR CI run")
        pull_requests = workflow_run.get("pull_requests") or []
        if len(pull_requests) != 1:
            raise SkipAutomation("the CI run has no unique associated pull request")
        number = pull_requests[0].get("number")
    else:
        raise SkipAutomation("this workflow event cannot refresh Dependabot branches")

    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise SkipAutomation("the merged pull request has no valid number")
    return number


def refresh_open_dependabot_branches(
    api: GitHubApi,
    repository: str,
    event_name: str,
    event: dict[str, Any],
) -> None:
    number = merged_pr_number_from_event(event_name, event)

    merged_pr = api.get(api_path(repository, f"/pulls/{number}"))
    if (
        merged_pr.get("state") != "closed"
        or not merged_pr.get("merged_at")
        or not is_same_repository_dependabot_pull_request(merged_pr, repository)
        or merged_pr.get("base", {}).get("ref") != "master"
    ):
        raise SkipAutomation("the merged pull request is not an eligible Dependabot update")

    merged_files = api.get_all(
        api_path(repository, f"/pulls/{number}/files?per_page=100")
    )
    if not auto_merge_scope_allowed(merged_files, merged_pr.get("changed_files")):
        raise SkipAutomation("the merged pull request was outside the dependency auto-merge scope")

    open_prs = api.get_all(
        api_path(repository, "/pulls?state=open&base=master&per_page=100")
    )
    for pull_request in open_prs:
        if not is_auto_merge_eligible(pull_request, repository):
            continue

        pull_number = pull_request.get("number")
        head_sha = pull_request.get("head", {}).get("sha")
        if not isinstance(pull_number, int) or not isinstance(head_sha, str):
            continue

        files = api.get_all(
            api_path(repository, f"/pulls/{pull_number}/files?per_page=100")
        )
        if not auto_merge_scope_allowed(files, pull_request.get("changed_files")):
            continue

        current_pr = api.get(api_path(repository, f"/pulls/{pull_number}"))
        if (
            current_pr.get("head", {}).get("sha") != head_sha
            or not should_update_dependabot_branch(current_pr, repository)
        ):
            continue

        try:
            api.put(
                api_path(repository, f"/pulls/{pull_number}/update-branch"),
                {"expected_head_sha": head_sha},
            )
        except GitHubApiError as error:
            if "HTTP 403" in str(error):
                raise GitHubApiError(
                    "branch update was denied; ADMIN_PAT must have repository "
                    "Pull requests: write permission"
                ) from None
            print(
                f"Could not update Dependabot PR #{pull_number}; it may have "
                "changed concurrently or have a merge conflict."
            )
            continue
        print(
            f"Requested update of Dependabot PR #{pull_number} onto the latest master; "
            "the token-authored branch update will start CI on the new head."
        )


def event_targets_auto_merge_branch(
    event_name: str,
    event: dict[str, Any],
    pull_request: dict[str, Any],
) -> bool:
    # workflow_run's associated PR payload omits the author; the live PR is
    # checked by process_pull_request before any merge state can be changed.
    if event_name != "workflow_run" and not is_dependabot_pull_request(pull_request):
        return False
    if pull_request.get("base", {}).get("ref") == "master":
        return True
    if event_name == "pull_request_target" and event.get("action") == "edited":
        changes = event.get("changes") or {}
        base_change = changes.get("base") or {}
        ref_change = base_change.get("ref") or {}
        return ref_change.get("from") == "master"
    return False


def latest_ci_run_for_pull_request(
    api: GitHubApi,
    repository: str,
    pull_request: dict[str, Any],
) -> dict[str, Any]:
    head_sha = pull_request.get("head", {}).get("sha")
    number = pull_request.get("number")
    if not head_sha or not isinstance(number, int):
        raise SkipAutomation("pull request event is missing its number or head SHA")
    query = urllib.parse.urlencode(
        {"head_sha": head_sha, "event": "pull_request", "per_page": 100}
    )
    response = api.get(api_path(repository, f"/actions/runs?{query}"))
    runs = response.get("workflow_runs") or []
    matching = [
        run
        for run in runs
        if run.get("name") == "CI"
        and run.get("path") == ".github/workflows/ci.yml"
        and run.get("head_sha") == head_sha
        and any(
            associated_pr.get("number") == number
            and associated_pr.get("head", {}).get("sha") == head_sha
            for associated_pr in run.get("pull_requests") or []
        )
    ]
    if not matching:
        raise SkipAutomation(f"PR #{number} has no CI run for its current head")
    latest = max(
        matching,
        key=lambda run: (run.get("run_number", 0), run.get("created_at", "")),
    )
    if latest.get("status") != "completed" or latest.get("conclusion") != "success":
        raise SkipAutomation(f"PR #{number} has no successful CI run for its current head")
    return latest


def process_pull_request(
    api: GitHubApi,
    repository: str,
    workflow_run: dict[str, Any] | None,
    event_pr: dict[str, Any],
    protection_confirmed: bool,
) -> None:
    number = event_pr.get("number")
    if not isinstance(number, int):
        raise SkipAutomation("the CI run has no associated pull request number")

    pr = api.get(api_path(repository, f"/pulls/{number}"))
    if not is_dependabot_pull_request(pr):
        raise SkipAutomation(f"PR #{number} was not created by Dependabot")
    if not is_auto_merge_eligible(pr, repository):
        raise SkipAutomation(f"Dependabot PR #{number} is not eligible for master auto-merge")

    files = api.get_all(
        api_path(repository, f"/pulls/{number}/files?per_page=100")
    )
    if not auto_merge_scope_allowed(files, pr.get("changed_files")):
        raise SkipAutomation(
            f"Dependabot PR #{number} changes a protected path or has an incomplete file list"
        )

    head = pr.get("head", {})
    if head.get("sha") != event_pr.get("head", {}).get("sha"):
        raise SkipAutomation(f"PR #{number} changed after this CI run")

    if workflow_run is None:
        workflow_run = latest_ci_run_for_pull_request(api, repository, pr)
    if workflow_run.get("head_sha") != head.get("sha"):
        raise SkipAutomation(f"PR #{number} CI run is for a different head SHA")

    ci_run_id = str(workflow_run["id"])
    jobs_passed, jobs_state, job_names = wait_for_required_jobs(
        lambda: ci_jobs_for_run(api, repository, ci_run_id),
        workflow_run.get("run_attempt", 1),
    )
    if not jobs_passed:
        if jobs_state == "pending":
            reason = (
                f"required CI jobs were still missing or incomplete after "
                f"{CI_JOB_READ_ATTEMPTS} reads: {', '.join(job_names)}"
            )
        elif jobs_state == "invalid":
            reason = f"GitHub returned duplicate required CI jobs: {', '.join(job_names)}"
        else:
            reason = f"required CI jobs did not pass: {', '.join(job_names)}"
        raise SkipAutomation(f"PR #{number} {reason}")

    if not protection_confirmed:
        raise SkipAutomation(
            "set CHIMERA_AUTOMERGE_PROTECTION_CONFIRMED=true after configuring master protections"
        )

    settings = api.get(f"/repos/{repository}")
    if settings.get("default_branch") != "master":
        raise SkipAutomation("the repository default branch is not master")

    latest_pr = api.get(api_path(repository, f"/pulls/{number}"))
    latest_head = latest_pr.get("head", {})
    if not is_dependabot_pull_request(latest_pr):
        raise SkipAutomation(f"PR #{number} is no longer a Dependabot PR")
    if not is_auto_merge_eligible(latest_pr, repository):
        raise SkipAutomation(f"Dependabot PR #{number} became ineligible during auto-merge preflight")
    if latest_head.get("sha") != head.get("sha"):
        raise SkipAutomation(f"PR #{number} changed during auto-merge preflight")
    if latest_pr.get("base", {}).get("sha") != pr.get("base", {}).get("sha"):
        raise SkipAutomation(f"PR #{number} base changed during auto-merge preflight")
    latest_files = api.get_all(
        api_path(repository, f"/pulls/{number}/files?per_page=100")
    )
    if not auto_merge_scope_allowed(latest_files, latest_pr.get("changed_files")):
        raise SkipAutomation(
            f"Dependabot PR #{number} changes a protected path or has an incomplete file list"
        )

    merge_when_ready(api, repository, latest_pr, latest_head["sha"])
    print(f"Merged eligible Dependabot PR #{number} through GitHub.")


def self_test() -> None:
    successful_jobs = [
        {"name": name, "status": "completed", "conclusion": "success", "run_attempt": 1}
        for name in EXPECTED_CI_JOBS
    ]
    assert required_jobs_passed(successful_jobs, 1)
    assert not required_jobs_passed(successful_jobs[:-1], 1)
    assert not required_jobs_passed(
        [
            {
                **job,
                "conclusion": "failure" if job["name"] == "Lint" else "success",
            }
            for job in successful_jobs
        ],
        1,
    )
    assert not required_jobs_passed(
        successful_jobs + [successful_jobs[0]],
        1,
    )
    duplicate_fetch_count = 0

    def fetch_duplicate_jobs() -> list[dict[str, Any]]:
        nonlocal duplicate_fetch_count
        duplicate_fetch_count += 1
        return successful_jobs + [successful_jobs[0]]

    assert wait_for_required_jobs(
        fetch_duplicate_jobs,
        1,
        max_attempts=3,
        retry_delay_seconds=0,
        sleep=lambda _: None,
    ) == (False, "invalid", [successful_jobs[0]["name"]])
    assert duplicate_fetch_count == 1
    assert required_jobs_status(successful_jobs[:-1], 1)[0] == "pending"
    assert required_jobs_status(
        [
            {
                **job,
                "conclusion": "failure" if job["name"] == "Lint" else "success",
            }
            for job in successful_jobs
        ],
        1,
    ) == ("failed", ["Lint"])

    transient_job_responses = [successful_jobs[:-1], successful_jobs]
    transient_fetch_count = 0
    retry_delays: list[float] = []

    def fetch_transient_jobs() -> list[dict[str, Any]]:
        nonlocal transient_fetch_count
        response_index = min(transient_fetch_count, len(transient_job_responses) - 1)
        transient_fetch_count += 1
        return transient_job_responses[response_index]

    assert wait_for_required_jobs(
        fetch_transient_jobs,
        1,
        max_attempts=3,
        retry_delay_seconds=2,
        sleep=retry_delays.append,
    ) == (True, "passed", [])
    assert transient_fetch_count == 2
    assert retry_delays == [2]

    incomplete_fetch_count = 0
    incomplete_jobs = [
        job for job in successful_jobs if job["name"] != "Required checks"
    ]

    def fetch_incomplete_jobs() -> list[dict[str, Any]]:
        nonlocal incomplete_fetch_count
        incomplete_fetch_count += 1
        return incomplete_jobs

    assert wait_for_required_jobs(
        fetch_incomplete_jobs,
        1,
        max_attempts=3,
        retry_delay_seconds=0,
        sleep=lambda _: None,
    ) == (False, "pending", ["Required checks"])
    assert incomplete_fetch_count == 3

    failed_fetch_count = 0

    def fetch_failed_jobs() -> list[dict[str, Any]]:
        nonlocal failed_fetch_count
        failed_fetch_count += 1
        return [
            {
                **job,
                "conclusion": "failure" if job["name"] == "Lint" else "success",
            }
            for job in successful_jobs
        ]

    assert wait_for_required_jobs(
        fetch_failed_jobs,
        1,
        max_attempts=3,
        retry_delay_seconds=0,
        sleep=lambda _: None,
    ) == (False, "failed", ["Lint"])
    assert failed_fetch_count == 1

    class PaginatedApiStub(GitHubApi):
        def __init__(self, pages: list[tuple[Any, dict[str, str]]]) -> None:
            super().__init__("test-token")
            self.pages = pages
            self.requested_urls: list[str] = []

        def request(
            self,
            url: str,
            payload: dict[str, Any] | None = None,
            method: str | None = None,
        ) -> tuple[Any, dict[str, str]]:
            assert payload is None
            assert method is None
            self.requested_urls.append(url)
            return self.pages.pop(0)

    first_jobs_page = [successful_jobs[0]]
    second_jobs_page = successful_jobs[1:]
    jobs_api = PaginatedApiStub(
        [
            (
                {"total_count": len(successful_jobs), "jobs": first_jobs_page},
                {"Link": '<https://api.github.com/jobs?page=2>; rel="next"'},
            ),
            ({"total_count": len(successful_jobs), "jobs": second_jobs_page}, {}),
        ]
    )
    assert ci_jobs_for_run(
        jobs_api, "MFSGA/Chimera_Server", "123"
    ) == first_jobs_page + second_jobs_page
    assert jobs_api.requested_urls == [
        "https://api.github.com/repos/MFSGA/Chimera_Server/actions/runs/123/jobs?per_page=100",
        "https://api.github.com/jobs?page=2",
    ]
    events_api = PaginatedApiStub([([{"event": "labeled"}], {})])
    assert events_api.get_all("/issues/123/events?per_page=100") == [
        {"event": "labeled"}
    ]
    malformed_jobs_api = PaginatedApiStub([({"total_count": 1, "workflow_runs": []}, {})])
    try:
        malformed_jobs_api.get_all("/actions/runs/123/jobs", collection_key="jobs")
    except GitHubApiError as error:
        assert str(error) == "GitHub API response did not contain a jobs list"
    else:
        raise AssertionError("malformed jobs response was accepted")

    assert protection_confirmation_enabled("true")
    assert not protection_confirmation_enabled(None)
    assert not protection_confirmation_enabled("True")
    assert not protection_confirmation_enabled("false")

    class MergeFlowApiStub:
        def __init__(self) -> None:
            self.put_calls: list[tuple[str, dict[str, Any]]] = []

        def put(self, path: str, payload: dict[str, Any]) -> dict[str, bool]:
            self.put_calls.append((path, payload))
            return {"merged": True}

        def get(self, path: str) -> dict[str, Any]:
            raise AssertionError(f"unexpected API read: {path}")

    immediate_merge_api = MergeFlowApiStub()
    merge_when_ready(
        immediate_merge_api,
        "MFSGA/Chimera_Server",
        {"number": 42, "mergeable_state": "clean"},
        "head-sha",
    )
    assert immediate_merge_api.put_calls == [
        (
            "/repos/MFSGA/Chimera_Server/pulls/42/merge",
            {"sha": "head-sha", "merge_method": "squash"},
        )
    ]
    unstable_merge_api = MergeFlowApiStub()
    merge_when_ready(
        unstable_merge_api,
        "MFSGA/Chimera_Server",
        {"number": 43, "mergeable_state": "unstable", "mergeable": True},
        "head-sha-unstable",
    )
    assert unstable_merge_api.put_calls == [
        (
            "/repos/MFSGA/Chimera_Server/pulls/43/merge",
            {"sha": "head-sha-unstable", "merge_method": "squash"},
        )
    ]
    class RefusedMergeApiStub(MergeFlowApiStub):
        def __init__(self, status_code: int) -> None:
            super().__init__()
            self.status_code = status_code

        def put(self, path: str, payload: dict[str, Any]) -> dict[str, bool]:
            self.put_calls.append((path, payload))
            raise GitHubApiError(f"GitHub API returned HTTP {self.status_code}")

    for status_code in (405, 409):
        refused_merge_api = RefusedMergeApiStub(status_code)
        try:
            merge_when_ready(
                refused_merge_api,
                "MFSGA/Chimera_Server",
                {"number": 44, "mergeable_state": "unstable", "mergeable": True},
                "head-sha-refused",
            )
        except SkipAutomation as skip:
            assert "required checks" in str(skip)
        else:
            raise AssertionError("GitHub merge refusal was not treated as a safe skip")
        assert refused_merge_api.put_calls == [
            (
                "/repos/MFSGA/Chimera_Server/pulls/44/merge",
                {"sha": "head-sha-refused", "merge_method": "squash"},
            )
        ]
    blocked_merge_api = MergeFlowApiStub()
    try:
        merge_when_ready(
            blocked_merge_api,
            "MFSGA/Chimera_Server",
            {"number": 42, "mergeable_state": "blocked"},
            "head-sha",
        )
    except SkipAutomation as skip:
        assert "merge gates" in str(skip)
    else:
        raise AssertionError("PR with unsatisfied merge gates was merged")
    assert not blocked_merge_api.put_calls
    non_mergeable_api = MergeFlowApiStub()
    try:
        merge_when_ready(
            non_mergeable_api,
            "MFSGA/Chimera_Server",
            {"number": 45, "mergeable_state": "unstable", "mergeable": False},
            "head-sha-conflict",
        )
    except SkipAutomation as skip:
        assert "merge gates" in str(skip)
    else:
        raise AssertionError("unstable PR with merge conflicts was passed to GitHub")
    assert not non_mergeable_api.put_calls

    eligible_pr = {
        "state": "open",
        "draft": False,
        "changed_files": 1,
        "user": {"login": "dependabot[bot]"},
        "base": {"ref": "master"},
        "head": {
            "sha": "head-sha",
            "repo": {"full_name": "MFSGA/Chimera_Server"},
        },
        "labels": [],
    }
    assert is_auto_merge_eligible(eligible_pr, "MFSGA/Chimera_Server")
    assert not is_auto_merge_eligible(
        {**eligible_pr, "state": "closed"}, "MFSGA/Chimera_Server"
    )
    assert not is_auto_merge_eligible(
        {**eligible_pr, "draft": True}, "MFSGA/Chimera_Server"
    )
    assert not is_auto_merge_eligible(
        {**eligible_pr, "base": {"ref": "develop"}}, "MFSGA/Chimera_Server"
    )
    ordinary_pr = {**eligible_pr, "user": {"login": "human-maintainer"}}
    assert not is_dependabot_pull_request(ordinary_pr)
    assert not is_auto_merge_eligible(ordinary_pr, "MFSGA/Chimera_Server")
    assert should_update_dependabot_branch(
        {**eligible_pr, "mergeable_state": "behind"}, "MFSGA/Chimera_Server"
    )
    assert not should_update_dependabot_branch(
        {**eligible_pr, "mergeable_state": "clean"}, "MFSGA/Chimera_Server"
    )
    assert not should_update_dependabot_branch(
        {**ordinary_pr, "mergeable_state": "behind"}, "MFSGA/Chimera_Server"
    )
    assert merged_pr_number_from_event(
        "pull_request_target",
        {"action": "closed", "pull_request": {"number": 42, "merged": True}},
    ) == 42
    assert merged_pr_number_from_event(
        "workflow_run",
        {
            "workflow_run": {
                "name": "CI",
                "path": ".github/workflows/ci.yml",
                "event": "pull_request",
                "conclusion": "success",
                "pull_requests": [{"number": 43}],
            }
        },
    ) == 43
    for invalid_refresh_event in (
        ("pull_request_target", {"action": "closed", "pull_request": {"merged": False}}),
        ("workflow_run", {"workflow_run": {"event": "push", "pull_requests": []}}),
        ("workflow_dispatch", {"inputs": {"merged_pr_number": "42"}}),
    ):
        try:
            merged_pr_number_from_event(*invalid_refresh_event)
        except SkipAutomation:
            pass
        else:
            raise AssertionError("invalid branch-refresh event was accepted")
    assert not is_auto_merge_eligible(
        {
            **eligible_pr,
            "head": {"sha": "head-sha", "repo": {"full_name": "contributor/fork"}},
        },
        "MFSGA/Chimera_Server",
    )
    assert auto_merge_scope_allowed([{"filename": "Cargo.lock"}], 1)
    assert auto_merge_scope_allowed([{"filename": "chimera_server_lib/Cargo.toml"}], 1)
    assert not auto_merge_scope_allowed([{"filename": "README.md"}], 1)
    old_action_sha = "02cb101ec7c40f2c49e1d9714d64511d8e1b74de"
    new_action_sha = "683b588c487a69d01f6c6ddf40f036ff682cc2c8"
    another_action_sha = "a" * 40
    action_pin_update = {
        "filename": ".github/workflows/release.yml",
        "status": "modified",
        "patch": (
            "@@ -45,1 +45,1 @@\n"
            f"-          uses: dtolnay/rust-toolchain@{old_action_sha} # stable\n"
            f"+          uses: dtolnay/rust-toolchain@{new_action_sha} # stable"
        ),
    }
    assert auto_merge_scope_allowed([action_pin_update], 1)
    list_action_pin_update = {
        **action_pin_update,
        "patch": action_pin_update["patch"].replace("uses:", "- uses:"),
    }
    assert auto_merge_scope_allowed([list_action_pin_update], 1)
    assert not auto_merge_scope_allowed(
        [
            {
                **action_pin_update,
                "patch": action_pin_update["patch"].replace(
                    "+          uses:", "+          - uses:"
                ),
            }
        ],
        1,
    )
    mixed_structure_pair_swap = {
        **action_pin_update,
        "patch": (
            "@@ -10,2 +10,2 @@\n"
            f"-          uses: example/action@{old_action_sha}\n"
            f"-          - uses: example/action@{new_action_sha}\n"
            f"+          - uses: example/action@{another_action_sha}\n"
            f"+          uses: example/action@{new_action_sha}"
        ),
    }
    assert not auto_merge_scope_allowed([mixed_structure_pair_swap], 1)
    unchanged_structure_pair = {
        **action_pin_update,
        "patch": (
            "@@ -10,2 +10,2 @@\n"
            f"-          uses: example/action@{old_action_sha}\n"
            f"-          uses: example/action@{new_action_sha}\n"
            f"+          uses: example/action@{new_action_sha}\n"
            f"+          uses: example/action@{another_action_sha}"
        ),
    }
    assert auto_merge_scope_allowed([unchanged_structure_pair], 1)
    assert not auto_merge_scope_allowed(
        [
            {
                **action_pin_update,
                "patch": action_pin_update["patch"].replace(
                    "+          uses:", "+            uses:"
                ),
            }
        ],
        1,
    )
    assert auto_merge_scope_allowed(
        [
            {
                **action_pin_update,
                "filename": ".github/actions/rust-ci-setup/action.yml",
            }
        ],
        1,
    )
    for unsafe_action_update in (
        {
            **action_pin_update,
            "patch": action_pin_update["patch"] + "\n+          run: echo unsafe",
        },
        {
            **action_pin_update,
            "patch": action_pin_update["patch"].replace(
                f"{new_action_sha} # stable", "v2 # stable"
            ),
        },
        {**action_pin_update, "filename": ".github/scripts/auto_merge.yml"},
        {**action_pin_update, "patch": None},
        {**action_pin_update, "status": "added"},
    ):
        assert not auto_merge_scope_allowed([unsafe_action_update], 1)
    assert not auto_merge_scope_allowed(
        [action_pin_update, {"filename": "Cargo.lock"}], 2
    )
    for protected_path in (
        ".github/workflows/ci.yml",
        "docs/ai-development-governance.md",
        "ref/xray-core/config.go",
        "vendor/dependency/src/lib.rs",
        "release/notes.md",
        "install.sh",
        "AGENTS.md",
        "LESSONS.md",
        "CODEOWNERS",
        "docs/CODEOWNERS",
    ):
        assert not auto_merge_scope_allowed([{"filename": protected_path}], 1)
    assert not auto_merge_scope_allowed([], 1)
    assert not auto_merge_scope_allowed([{}], 1)
    assert event_targets_auto_merge_branch(
        "pull_request_target", {"action": "opened"}, eligible_pr
    )
    assert not event_targets_auto_merge_branch(
        "pull_request_target", {"action": "opened"}, ordinary_pr
    )
    # The workflow_run PR summary omits `user`; the live API fetch performs the
    # authoritative Dependabot check before any merge request is made.
    assert event_targets_auto_merge_branch(
        "workflow_run", {}, {"number": 42, "base": {"ref": "master"}}
    )
    non_master_pr = {**eligible_pr, "base": {"ref": "develop"}}
    assert not event_targets_auto_merge_branch(
        "pull_request_target", {"action": "opened"}, non_master_pr
    )
    assert event_targets_auto_merge_branch(
        "pull_request_target",
        {
            "action": "edited",
            "changes": {"base": {"ref": {"from": "master"}}},
        },
        non_master_pr,
    )

    class OrdinaryPullRequestApiStub(MergeFlowApiStub):
        def get(self, path: str) -> dict[str, Any]:
            assert path == "/repos/MFSGA/Chimera_Server/pulls/42"
            return {**eligible_pr, "user": {"login": "human-maintainer"}}

    ordinary_api = OrdinaryPullRequestApiStub()
    try:
        process_pull_request(
            ordinary_api,
            "MFSGA/Chimera_Server",
            {"id": 123, "head_sha": "head-sha", "run_attempt": 1},
            {"number": 42, "head": {"sha": "head-sha"}},
            protection_confirmed=True,
        )
    except SkipAutomation as skip:
        assert "not created by Dependabot" in str(skip)
    else:
        raise AssertionError("ordinary pull request was accepted for auto-merge")
    assert not ordinary_api.put_calls

    class ProtectedPathPullRequestApiStub(MergeFlowApiStub):
        def get(self, path: str) -> dict[str, Any]:
            assert path == "/repos/MFSGA/Chimera_Server/pulls/42"
            return {
                **eligible_pr,
                "number": 42,
                "node_id": "PR_node",
                "changed_files": 1,
            }

        def get_all(
            self,
            path: str,
            *,
            collection_key: str | None = None,
        ) -> list[Any]:
            assert path == "/repos/MFSGA/Chimera_Server/pulls/42/files?per_page=100"
            assert collection_key is None
            return [{"filename": ".github/workflows/ci.yml"}]

    protected_path_api = ProtectedPathPullRequestApiStub()
    try:
        process_pull_request(
            protected_path_api,
            "MFSGA/Chimera_Server",
            {"id": 123, "head_sha": "head-sha", "run_attempt": 1},
            {"number": 42, "head": {"sha": "head-sha"}},
            protection_confirmed=True,
        )
    except SkipAutomation as skip:
        assert "protected path" in str(skip)
    else:
        raise AssertionError("Dependabot workflow change was accepted for auto-merge")
    assert not protected_path_api.put_calls

    assert not event_targets_auto_merge_branch(
        "pull_request_target",
        {
            "action": "edited",
            "changes": {"base": {"ref": {"from": "develop"}}},
        },
        non_master_pr,
    )

    class EligiblePullRequestApiStub(MergeFlowApiStub):
        def __init__(self) -> None:
            super().__init__()
            self.pull_requests = [dict(eligible_pr), dict(eligible_pr)]

        def get(self, path: str) -> dict[str, Any]:
            if path == "/repos/MFSGA/Chimera_Server/pulls/42":
                return self.pull_requests.pop(0)
            if path == "/repos/MFSGA/Chimera_Server":
                return {"default_branch": "master"}
            raise AssertionError(f"unexpected API read: {path}")

        def get_all(
            self,
            path: str,
            *,
            collection_key: str | None = None,
        ) -> list[Any]:
            if path == "/repos/MFSGA/Chimera_Server/pulls/42/files?per_page=100":
                assert collection_key is None
                return [{"filename": "Cargo.lock"}]
            if path == (
                "/repos/MFSGA/Chimera_Server/actions/runs/123/jobs?per_page=100"
            ):
                assert collection_key == "jobs"
                return successful_jobs
            raise AssertionError(f"unexpected API list: {path}")

    eligible_pr.update(
        {
            "number": 42,
            "base": {"ref": "master", "sha": "base-sha"},
            "mergeable_state": "clean",
            "changed_files": 1,
        }
    )

    merged_dependabot_pr = {
        **eligible_pr,
        "state": "closed",
        "merged_at": "2026-10-26T12:00:00Z",
    }
    behind_dependabot_pr = {
        **eligible_pr,
        "number": 43,
        "mergeable_state": "behind",
        "head": {
            "sha": "behind-head-sha",
            "repo": {"full_name": "MFSGA/Chimera_Server"},
        },
    }
    current_dependabot_pr = {
        **eligible_pr,
        "number": 44,
        "mergeable_state": "clean",
        "head": {
            "sha": "current-head-sha",
            "repo": {"full_name": "MFSGA/Chimera_Server"},
        },
    }

    class RefreshDependabotBranchesApiStub:
        def __init__(self) -> None:
            self.put_calls: list[tuple[str, dict[str, Any]]] = []

        def get(self, path: str) -> dict[str, Any]:
            if path == "/repos/MFSGA/Chimera_Server/pulls/42":
                return merged_dependabot_pr
            if path == "/repos/MFSGA/Chimera_Server/pulls/43":
                return behind_dependabot_pr
            if path == "/repos/MFSGA/Chimera_Server/pulls/44":
                return current_dependabot_pr
            raise AssertionError(f"unexpected API read: {path}")

        def get_all(
            self,
            path: str,
            *,
            collection_key: str | None = None,
        ) -> list[Any]:
            assert collection_key is None
            if path == "/repos/MFSGA/Chimera_Server/pulls?state=open&base=master&per_page=100":
                return [behind_dependabot_pr, current_dependabot_pr]
            if path in {
                "/repos/MFSGA/Chimera_Server/pulls/42/files?per_page=100",
                "/repos/MFSGA/Chimera_Server/pulls/43/files?per_page=100",
                "/repos/MFSGA/Chimera_Server/pulls/44/files?per_page=100",
            }:
                return [{"filename": "Cargo.lock"}]
            raise AssertionError(f"unexpected API list: {path}")

        def put(self, path: str, payload: dict[str, Any]) -> dict[str, str]:
            self.put_calls.append((path, payload))
            return {"message": "Updating pull request branch."}

    refresh_api = RefreshDependabotBranchesApiStub()
    refresh_open_dependabot_branches(
        refresh_api,
        "MFSGA/Chimera_Server",
        "pull_request_target",
        {"action": "closed", "pull_request": {"number": 42, "merged": True}},
    )
    assert refresh_api.put_calls == [
        (
            "/repos/MFSGA/Chimera_Server/pulls/43/update-branch",
            {"expected_head_sha": "behind-head-sha"},
        )
    ]

    eligible_api = EligiblePullRequestApiStub()
    process_pull_request(
        eligible_api,
        "MFSGA/Chimera_Server",
        {"id": 123, "head_sha": "head-sha", "run_attempt": 1},
        {"number": 42, "head": {"sha": "head-sha"}},
        protection_confirmed=True,
    )
    assert eligible_api.put_calls == [
        (
            "/repos/MFSGA/Chimera_Server/pulls/42/merge",
            {"sha": "head-sha", "merge_method": "squash"},
        )
    ]

    class EligibleActionPullRequestApiStub(EligiblePullRequestApiStub):
        def get_all(
            self,
            path: str,
            *,
            collection_key: str | None = None,
        ) -> list[Any]:
            if path == "/repos/MFSGA/Chimera_Server/pulls/42/files?per_page=100":
                assert collection_key is None
                return [action_pin_update]
            return super().get_all(path, collection_key=collection_key)

    eligible_action_api = EligibleActionPullRequestApiStub()
    process_pull_request(
        eligible_action_api,
        "MFSGA/Chimera_Server",
        {"id": 123, "head_sha": "head-sha", "run_attempt": 1},
        {"number": 42, "head": {"sha": "head-sha"}},
        protection_confirmed=True,
    )
    assert eligible_action_api.put_calls == eligible_api.put_calls

    class RetargetedPullRequestApiStub(EligiblePullRequestApiStub):
        def __init__(self) -> None:
            super().__init__()
            self.pull_requests = [
                dict(eligible_pr),
                {**eligible_pr, "base": {"ref": "master", "sha": "changed-base-sha"}},
            ]

    retargeted_api = RetargetedPullRequestApiStub()
    try:
        process_pull_request(
            retargeted_api,
            "MFSGA/Chimera_Server",
            {"id": 123, "head_sha": "head-sha", "run_attempt": 1},
            {"number": 42, "head": {"sha": "head-sha"}},
            protection_confirmed=True,
        )
    except SkipAutomation as skip:
        assert "base changed" in str(skip)
    else:
        raise AssertionError("PR with a changed base was merged")
    assert not retargeted_api.put_calls

    class NewlyProtectedFileApiStub(EligiblePullRequestApiStub):
        def __init__(self) -> None:
            super().__init__()
            self.file_reads = 0

        def get_all(
            self,
            path: str,
            *,
            collection_key: str | None = None,
        ) -> list[Any]:
            if path == "/repos/MFSGA/Chimera_Server/pulls/42/files?per_page=100":
                assert collection_key is None
                self.file_reads += 1
                return [
                    {
                        "filename": (
                            "Cargo.lock"
                            if self.file_reads == 1
                            else ".github/workflows/auto-merge.yml"
                        )
                    }
                ]
            return super().get_all(path, collection_key=collection_key)

    newly_protected_file_api = NewlyProtectedFileApiStub()
    try:
        process_pull_request(
            newly_protected_file_api,
            "MFSGA/Chimera_Server",
            {"id": 123, "head_sha": "head-sha", "run_attempt": 1},
            {"number": 42, "head": {"sha": "head-sha"}},
            protection_confirmed=True,
        )
    except SkipAutomation as skip:
        assert "protected path" in str(skip)
    else:
        raise AssertionError("PR with a protected file at final check was merged")
    assert newly_protected_file_api.file_reads == 2
    assert not newly_protected_file_api.put_calls

    blocked_pr = {**eligible_pr, "mergeable_state": "blocked"}
    blocked_api = EligiblePullRequestApiStub()
    blocked_api.pull_requests = [dict(blocked_pr), dict(blocked_pr)]
    try:
        process_pull_request(
            blocked_api,
            "MFSGA/Chimera_Server",
            {"id": 123, "head_sha": "head-sha", "run_attempt": 1},
            {"number": 42, "head": {"sha": "head-sha"}},
            protection_confirmed=True,
        )
    except SkipAutomation as skip:
        assert "merge gates" in str(skip)
    else:
        raise AssertionError("Dependabot PR with unsatisfied gates was merged")
    assert not blocked_api.put_calls
    print("Auto-merge policy self-test passed.")


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if sys.argv[1:]:
        print("Usage: auto_merge_after_ci.py [--self-test]", file=sys.stderr)
        return 2

    try:
        with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as event_file:
            event = json.load(event_file)
        token = os.environ.get("GH_TOKEN", "")
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        if not token or not repository:
            raise GitHubApiError("required GitHub Actions environment is missing")
        protection_confirmed = protection_confirmation_enabled(
            os.environ.get("CHIMERA_AUTOMERGE_PROTECTION_CONFIRMED")
        )
        api = GitHubApi(token)
        event_name = os.environ.get("GITHUB_EVENT_NAME", "")
        if os.environ.get("AUTOMERGE_MODE") == "refresh":
            refresh_open_dependabot_branches(api, repository, event_name, event)
            return 0
        if event_name == "pull_request_target" and event.get("action") == "closed":
            refresh_open_dependabot_branches(api, repository, event_name, event)
            return 0
        if event_name == "workflow_run":
            workflow_run = event.get("workflow_run", {})
            if (
                workflow_run.get("name") != "CI"
                or workflow_run.get("path") != ".github/workflows/ci.yml"
                or workflow_run.get("event") != "pull_request"
                or workflow_run.get("conclusion") != "success"
            ):
                raise SkipAutomation("the completed workflow is not a successful PR CI run")
            run_id = str(workflow_run.get("id", ""))
            if not run_id or run_id != os.environ.get("WORKFLOW_RUN_ID"):
                raise SkipAutomation("workflow-run ID does not match the event")
            pull_requests = workflow_run.get("pull_requests") or []
            if not pull_requests:
                raise SkipAutomation("the CI run has no associated pull request")
            if len(pull_requests) != 1:
                raise SkipAutomation("the CI run is associated with multiple PRs; refusing ambiguous serialization")
        elif event_name in {"pull_request_target", "pull_request_review"}:
            event_pr = event.get("pull_request") or {}
            action = event.get("action")
            if event_name == "pull_request_target":
                if action not in {
                    "opened",
                    "reopened",
                    "synchronize",
                    "edited",
                    "ready_for_review",
                    "converted_to_draft",
                }:
                    raise SkipAutomation("the pull request event does not affect merge authorization")
            elif action not in {"submitted", "edited", "dismissed"}:
                raise SkipAutomation("the pull request review event is not actionable")
            pull_requests = [event_pr]
            workflow_run = None
        else:
            raise SkipAutomation("this workflow event does not authorize auto-merge checks")

        for event_pr in pull_requests:
            if not event_targets_auto_merge_branch(event_name, event, event_pr):
                print(
                    f"Skipping PR #{event_pr.get('number', '?')}: "
                    "it does not target master or change away from master"
                )
                continue
            try:
                process_pull_request(
                    api,
                    repository,
                    workflow_run,
                    event_pr,
                    protection_confirmed,
                )
            except SkipAutomation as skip:
                print(f"Skipping PR #{event_pr.get('number', '?')}: {skip}")
        return 0
    except SkipAutomation as skip:
        print(f"Skipping auto-merge: {skip}")
        return 0
    except (GitHubApiError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"Auto-merge preflight failed safely: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
