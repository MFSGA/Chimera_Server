#!/usr/bin/env python3
"""Enable native GitHub Auto-merge for explicitly approved low-risk PRs."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
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
AUTO_MERGE_LABELS = frozenset({"automerge:l0", "automerge:l1"})
AUTO_MERGEABLE_DOCS = frozenset(
    {
        "README.md",
        "README.en.md",
        "README.fa.md",
        "README.ru.md",
    }
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

    def graphql(self, query: str, variables: dict[str, Any]) -> Any:
        value, _ = self.request(
            "https://api.github.com/graphql",
            {"query": query, "variables": variables},
        )
        if value.get("errors"):
            raise GitHubApiError("GitHub GraphQL request failed")
        return value["data"]


def next_link(header: str) -> str:
    for item in header.split(","):
        url, _, relation = item.strip().partition(";")
        if relation.strip() == 'rel="next"':
            return url.strip("<>")
    return ""


def required_jobs_passed(jobs: list[dict[str, Any]], attempt: int) -> bool:
    current: dict[str, dict[str, Any]] = {}
    for job in jobs:
        if job.get("run_attempt", attempt) != attempt:
            continue
        name = job.get("name")
        if name in EXPECTED_CI_JOBS:
            if name in current:
                return False
            current[name] = job
    return all(
        current.get(name, {}).get("status") == "completed"
        and current.get(name, {}).get("conclusion") == "success"
        for name in EXPECTED_CI_JOBS
    )


def protection_confirmation_enabled(value: str | None) -> bool:
    return value == "true"


def configured_maintainers(value: str | None) -> set[str]:
    return {
        login.strip().casefold()
        for login in (value or "").split(",")
        if login.strip()
    }


def high_risk_file(path: str) -> bool:
    return path not in AUTO_MERGEABLE_DOCS


def current_risk_label_actor(
    label: str,
    events: list[dict[str, Any]],
) -> str | None:
    history = [
        event
        for event in events
        if (event.get("label") or {}).get("name", "").lower() == label.lower()
        and event.get("event") in {"labeled", "unlabeled"}
    ]
    if not history:
        return None

    def event_order(event: dict[str, Any]) -> tuple[str, int]:
        try:
            event_id = int(event.get("id", 0))
        except (TypeError, ValueError):
            event_id = 0
        return event.get("created_at", ""), event_id

    latest = max(history, key=event_order)
    actor = (latest.get("actor") or {}).get("login", "")
    return actor if latest.get("event") == "labeled" and actor else None


def api_path(repository: str, suffix: str) -> str:
    owner, repo = repository.split("/", 1)
    return f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}{suffix}"


def ci_jobs_for_run(api: GitHubApi, repository: str, run_id: str) -> list[Any]:
    path = api_path(repository, f"/actions/runs/{run_id}/jobs?per_page=100")
    return api.get_all(path, collection_key="jobs")


def maintainer_applied_current_label(
    api: GitHubApi,
    label: str,
    author: str,
    events: list[dict[str, Any]],
    maintainers: set[str],
) -> bool:
    actor = current_risk_label_actor(label, events)
    if (
        not actor
        or actor.casefold() == author.casefold()
        or actor.casefold() not in maintainers
    ):
        return False
    user = api.get(f"/users/{urllib.parse.quote(actor, safe='')}")
    return user.get("type") == "User"


def enable_auto_merge(api: GitHubApi, pull_request: dict[str, Any]) -> None:
    api.graphql(
        """
        mutation EnableAutoMerge($pullRequestId: ID!) {
          enablePullRequestAutoMerge(input: {
            pullRequestId: $pullRequestId,
            mergeMethod: SQUASH
          }) {
            pullRequest { number autoMergeRequest { enabledAt } }
          }
        }
        """,
        {"pullRequestId": pull_request["node_id"]},
    )


def merge_pull_request(
    api: GitHubApi,
    repository: str,
    pull_request: dict[str, Any],
    expected_head_sha: str,
) -> None:
    result = api.put(
        api_path(repository, f"/pulls/{pull_request['number']}/merge"),
        {"sha": expected_head_sha, "merge_method": "squash"},
    )
    if result.get("merged") is not True:
        raise GitHubApiError("GitHub did not confirm the pull request merge")


def complete_or_queue_auto_merge(
    api: GitHubApi,
    repository: str,
    pull_request: dict[str, Any],
    expected_head_sha: str,
) -> bool:
    if pull_request.get("mergeable_state") == "clean":
        merge_pull_request(api, repository, pull_request, expected_head_sha)
        return False

    try:
        enable_auto_merge(api, pull_request)
        return True
    except GitHubApiError:
        # The PR can become clean after the last GET but before the GraphQL
        # mutation. In that race, finish with GitHub's head-SHA-guarded merge API.
        latest = api.get(api_path(repository, f"/pulls/{pull_request['number']}"))
        if (
            latest.get("mergeable_state") != "clean"
            or latest.get("head", {}).get("sha") != expected_head_sha
        ):
            raise
        merge_pull_request(api, repository, latest, expected_head_sha)
        return False


def disable_auto_merge(api: GitHubApi, pull_request: dict[str, Any]) -> None:
    pull_request_id = pull_request.get("node_id")
    if not pull_request_id:
        return
    current = api.graphql(
        """
        query AutoMergeState($pullRequestId: ID!) {
          node(id: $pullRequestId) {
            ... on PullRequest { autoMergeRequest { enabledAt } }
          }
        }
        """,
        {"pullRequestId": pull_request_id},
    )
    node = current.get("node") or {}
    if not node.get("autoMergeRequest"):
        return
    api.graphql(
        """
        mutation DisableAutoMerge($pullRequestId: ID!) {
          disablePullRequestAutoMerge(input: { pullRequestId: $pullRequestId }) {
            pullRequest { number }
          }
        }
        """,
        {"pullRequestId": pull_request_id},
    )
    number = pull_request.get("number", "?")
    print(f"Disabled stale GitHub Auto-merge request for PR #{number}.")


def should_cancel_auto_merge(
    action: str,
    event: dict[str, Any],
    pull_request: dict[str, Any],
    label_events: list[dict[str, Any]],
) -> bool:
    labels = {
        label.get("name", "").lower()
        for label in pull_request.get("labels", [])
    }
    changed_label = (event.get("label") or {}).get("name", "").lower()
    has_policy_history = any(
        (item.get("label") or {}).get("name", "").lower() in AUTO_MERGE_LABELS
        and item.get("event") in {"labeled", "unlabeled"}
        for item in label_events
    )
    return (
        action in {"synchronize", "edited", "labeled", "unlabeled"}
        and (
            bool(labels & AUTO_MERGE_LABELS)
            or changed_label in AUTO_MERGE_LABELS
            or has_policy_history
        )
    )


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
    workflow_run: dict[str, Any],
    event_pr: dict[str, Any],
    maintainers: set[str],
    protection_confirmed: bool,
) -> None:
    number = event_pr.get("number")
    if not isinstance(number, int):
        raise SkipAutomation("the CI run has no associated pull request number")

    pr = api.get(api_path(repository, f"/pulls/{number}"))
    if pr.get("state") != "open" or pr.get("draft"):
        raise SkipAutomation(f"PR #{number} is closed or draft")
    if pr.get("base", {}).get("ref") != "master":
        raise SkipAutomation(f"PR #{number} does not target master")
    head = pr.get("head", {})
    if not head.get("repo") or head["repo"].get("full_name") != repository:
        raise SkipAutomation(f"PR #{number} is not from this repository")
    if head.get("sha") != event_pr.get("head", {}).get("sha"):
        raise SkipAutomation(f"PR #{number} changed after this CI run")
    if workflow_run.get("head_sha") != head.get("sha"):
        raise SkipAutomation(f"PR #{number} CI run is for a different head SHA")

    if not required_jobs_passed(
        ci_jobs_for_run(api, repository, str(workflow_run["id"])),
        workflow_run.get("run_attempt", 1),
    ):
        raise SkipAutomation(f"PR #{number} is missing a successful required CI job")

    if not protection_confirmed:
        raise SkipAutomation(
            "set CHIMERA_AUTOMERGE_PROTECTION_CONFIRMED=true after configuring master protections"
        )

    labels = {label.get("name", "").lower() for label in pr.get("labels", [])}
    authorized_labels = labels & AUTO_MERGE_LABELS
    if len(authorized_labels) != 1:
        raise SkipAutomation(f"PR #{number} must have exactly one L0/L1 auto-merge label")

    events = api.get_all(api_path(repository, f"/issues/{number}/events?per_page=100"))
    author = pr.get("user", {}).get("login", "")
    label = next(iter(authorized_labels))
    if not maintainer_applied_current_label(api, label, author, events, maintainers):
        raise SkipAutomation(
            f"PR #{number} risk label was not applied by a different configured maintainer"
        )

    files = api.get_all(api_path(repository, f"/pulls/{number}/files?per_page=100"))
    if pr.get("changed_files", 0) != len(files):
        raise SkipAutomation(f"PR #{number} file list is incomplete")
    if any(high_risk_file(file.get("filename", "")) for file in files):
        raise SkipAutomation(f"PR #{number} changes protected/high-risk paths")

    settings = api.get(f"/repos/{repository}")
    if settings.get("allow_auto_merge") is not True:
        raise SkipAutomation("repository Auto-merge is disabled")
    if settings.get("default_branch") != "master":
        raise SkipAutomation("the repository default branch is not master")

    latest_pr = api.get(api_path(repository, f"/pulls/{number}"))
    latest_head = latest_pr.get("head", {})
    latest_labels = {
        label.get("name", "").lower() for label in latest_pr.get("labels", [])
    }
    latest_authorized_labels = latest_labels & AUTO_MERGE_LABELS
    if (
        latest_pr.get("state") != "open"
        or latest_pr.get("draft")
        or latest_pr.get("base", {}).get("ref") != "master"
        or not latest_head.get("repo")
        or latest_head["repo"].get("full_name") != repository
        or latest_head.get("sha") != head.get("sha")
        or latest_authorized_labels != {label}
    ):
        raise SkipAutomation(f"PR #{number} changed during auto-merge preflight")

    latest_events = api.get_all(
        api_path(repository, f"/issues/{number}/events?per_page=100")
    )
    if not maintainer_applied_current_label(
        api, label, author, latest_events, maintainers
    ):
        raise SkipAutomation(f"PR #{number} risk label authorization changed during preflight")
    latest_files = api.get_all(
        api_path(repository, f"/pulls/{number}/files?per_page=100")
    )
    if latest_pr.get("changed_files", 0) != len(latest_files) or any(
        high_risk_file(file.get("filename", "")) for file in latest_files
    ):
        raise SkipAutomation(f"PR #{number} file scope changed during auto-merge preflight")

    # If the PR is not ready, GitHub holds native Auto-merge until its required
    # gates pass. A clean PR cannot be queued, so merge it with the same head SHA.
    # Label revocation remains best-effort because there is no atomic
    # label-check-and-merge operation.
    if complete_or_queue_auto_merge(api, repository, latest_pr, latest_head["sha"]):
        print(f"Enabled GitHub Auto-merge for eligible PR #{number}.")
    else:
        print(f"Merged eligible PR #{number} through GitHub.")


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
    assert configured_maintainers(" Alice, bob ,") == {"alice", "bob"}
    assert configured_maintainers(None) == set()

    class UserLookupStub:
        def get(self, path: str) -> dict[str, str]:
            assert path == "/users/maintainer"
            return {"type": "User"}

    authorized_label_event = [
        {
            "event": "labeled",
            "label": {"name": "automerge:l1"},
            "actor": {"login": "maintainer"},
            "created_at": "2026-10-14T10:00:00Z",
        }
    ]
    assert maintainer_applied_current_label(
        UserLookupStub(),
        "automerge:l1",
        "pr-author",
        authorized_label_event,
        {"maintainer"},
    )
    assert not maintainer_applied_current_label(
        UserLookupStub(),
        "automerge:l1",
        "maintainer",
        authorized_label_event,
        {"maintainer"},
    )
    assert not maintainer_applied_current_label(
        UserLookupStub(),
        "automerge:l1",
        "pr-author",
        authorized_label_event,
        set(),
    )

    class MergeFlowApiStub:
        def __init__(self) -> None:
            self.put_calls: list[tuple[str, dict[str, Any]]] = []
            self.graphql_calls: list[str] = []

        def put(self, path: str, payload: dict[str, Any]) -> dict[str, bool]:
            self.put_calls.append((path, payload))
            return {"merged": True}

        def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
            self.graphql_calls.append(query)
            return {}

        def get(self, path: str) -> dict[str, Any]:
            raise AssertionError(f"unexpected API read: {path}")

    immediate_merge_api = MergeFlowApiStub()
    assert not complete_or_queue_auto_merge(
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
    assert not immediate_merge_api.graphql_calls

    queued_merge_api = MergeFlowApiStub()
    assert complete_or_queue_auto_merge(
        queued_merge_api,
        "MFSGA/Chimera_Server",
        {"number": 42, "mergeable_state": "blocked", "node_id": "PR_node"},
        "head-sha",
    )
    assert not queued_merge_api.put_calls
    assert len(queued_merge_api.graphql_calls) == 1

    class CleanRaceApiStub(MergeFlowApiStub):
        def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
            raise GitHubApiError("simulated clean-state auto-merge rejection")

        def get(self, path: str) -> dict[str, Any]:
            assert path == "/repos/MFSGA/Chimera_Server/pulls/42"
            return {
                "number": 42,
                "mergeable_state": "clean",
                "head": {"sha": "head-sha"},
            }

    clean_race_api = CleanRaceApiStub()
    assert not complete_or_queue_auto_merge(
        clean_race_api,
        "MFSGA/Chimera_Server",
        {"number": 42, "mergeable_state": "blocked", "node_id": "PR_node"},
        "head-sha",
    )
    assert len(clean_race_api.put_calls) == 1

    assert high_risk_file(".github/workflows/ci.yml")
    assert high_risk_file("chimera_server_lib/src/config/def.rs")
    assert high_risk_file("chimera_cli/src/main.rs")
    assert high_risk_file("Cargo.lock")
    assert high_risk_file("VLESS_REVERSE_DESIGN.md")
    assert not high_risk_file("README.md")
    assert not high_risk_file("README.en.md")
    events = [
        {
            "event": "labeled",
            "label": {"name": "automerge:l1"},
            "actor": {"login": "maintainer"},
            "created_at": "2026-10-14T10:00:00Z",
        }
    ]
    assert current_risk_label_actor("automerge:l1", events) == "maintainer"
    assert current_risk_label_actor(
        "automerge:l1",
        [{**events[0], "actor": {"login": "github-actions[bot]"}}],
    ) == "github-actions[bot]"
    assert current_risk_label_actor(
        "automerge:l1",
        [{**events[0], "event": "unlabeled"}],
    ) is None
    same_second_transitions = [
        {
            "id": 100,
            "event": "labeled",
            "label": {"name": "automerge:l1"},
            "actor": {"login": "maintainer"},
            "created_at": "2026-10-14T10:00:00Z",
        },
        {
            "id": 101,
            "event": "unlabeled",
            "label": {"name": "automerge:l1"},
            "actor": {"login": "author"},
            "created_at": "2026-10-14T10:00:00Z",
        },
        {
            "id": 102,
            "event": "labeled",
            "label": {"name": "automerge:l1"},
            "actor": {"login": "author"},
            "created_at": "2026-10-14T10:00:00Z",
        },
    ]
    assert current_risk_label_actor("automerge:l1", same_second_transitions) == "author"
    assert should_cancel_auto_merge(
        "synchronize",
        {},
        {"labels": [{"name": "automerge:l0"}]},
        [],
    )
    assert should_cancel_auto_merge(
        "unlabeled",
        {"label": {"name": "automerge:l1"}},
        {"labels": []},
        [],
    )
    assert not should_cancel_auto_merge(
        "synchronize",
        {},
        {"labels": [{"name": "bug"}]},
        [],
    )
    assert should_cancel_auto_merge(
        "labeled",
        {"label": {"name": "bug"}},
        {"labels": [{"name": "bug"}]},
        [{"event": "unlabeled", "label": {"name": "automerge:l0"}}],
    )
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
        maintainers = configured_maintainers(
            os.environ.get("CHIMERA_AUTOMERGE_MAINTAINERS")
        )
        protection_confirmed = protection_confirmation_enabled(
            os.environ.get("CHIMERA_AUTOMERGE_PROTECTION_CONFIRMED")
        )
        api = GitHubApi(token)
        event_name = os.environ.get("GITHUB_EVENT_NAME", "")
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
                if action not in {"synchronize", "unlabeled", "labeled", "edited"}:
                    raise SkipAutomation("the pull request event does not affect merge authorization")
                number = event_pr.get("number")
                label_events = (
                    api.get_all(api_path(repository, f"/issues/{number}/events?per_page=100"))
                    if isinstance(number, int)
                    else []
                )
                if should_cancel_auto_merge(action, event, event_pr, label_events):
                    disable_auto_merge(api, event_pr)
            elif action not in {"submitted", "edited", "dismissed"}:
                raise SkipAutomation("the pull request review event is not actionable")
            pull_requests = [event_pr]
            workflow_run = None
        else:
            raise SkipAutomation("this workflow event does not authorize auto-merge checks")

        for event_pr in pull_requests:
            try:
                current_run = workflow_run or latest_ci_run_for_pull_request(
                    api, repository, event_pr
                )
                process_pull_request(
                    api,
                    repository,
                    current_run,
                    event_pr,
                    maintainers,
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
