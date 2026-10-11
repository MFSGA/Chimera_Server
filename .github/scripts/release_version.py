#!/usr/bin/env python3
"""Compute and optionally apply the UTC calendar workspace release version."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import json
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path

VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
WORKSPACE_HEADER = "[workspace.package]"


def parse_version(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"expected stable X.Y.Z version, got {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def format_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def release_date_version(
    release_date: date,
    tags: list[tuple[int, int, int]] | tuple[tuple[int, int, int], ...] = (),
) -> str:
    """Format a release date as Xray-style YY.M.D, advancing for same-day releases."""
    if release_date.year < 2000 or release_date.year > 2099:
        raise ValueError("calendar release versions support years 2000 through 2099")
    year = release_date.year % 100
    month = release_date.month
    patch = release_date.day
    latest_month_patch = max(
        (tag[2] for tag in tags if tag[:2] == (year, month)),
        default=0,
    )
    if latest_month_patch >= patch:
        patch = latest_month_patch + 1
    return f"{year:02d}.{month}.{patch}"


def parse_release_date(value: str) -> date:
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        raise ValueError(f"expected release date YYYY-MM-DD, got {value!r}")
    try:
        release_date = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"expected release date YYYY-MM-DD, got {value!r}") from error
    if release_date.year < 2000 or release_date.year > 2099:
        raise ValueError("calendar release versions support years 2000 through 2099")
    return release_date


def read_workspace_version(path: Path) -> str:
    in_workspace_package = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == WORKSPACE_HEADER:
            in_workspace_package = True
            continue
        if line.startswith("["):
            in_workspace_package = False
        if in_workspace_package:
            match = re.fullmatch(r'version\s*=\s*"([^"]+)"', line)
            if match is not None:
                parse_version(match.group(1))
                return match.group(1)
    raise ValueError(f"could not find stable workspace.package version in {path}")


def workspace_package_names(path: Path) -> list[str]:
    root = tomllib.loads(path.read_text(encoding="utf-8"))
    members = root.get("workspace", {}).get("members", [])
    names: list[str] = []
    for member in members:
        manifest = path.parent / member / "Cargo.toml"
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        package = data.get("package", {})
        version = package.get("version")
        if isinstance(version, dict) and version.get("workspace") is True:
            name = package.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError(f"workspace member has no package name: {manifest}")
            names.append(name)
    if not names:
        raise ValueError("no workspace packages inherit workspace.package.version")
    return names


def write_workspace_version(path: Path, version: str) -> None:
    parse_version(version)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    in_workspace_package = False
    replaced = 0

    for index, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if stripped == WORKSPACE_HEADER:
            in_workspace_package = True
            continue
        if stripped.startswith("["):
            in_workspace_package = False
        if in_workspace_package and re.fullmatch(r'version\s*=\s*"[^"]+"', stripped):
            indent = raw_line[: len(raw_line) - len(raw_line.lstrip())]
            newline = "\n" if raw_line.endswith("\n") else ""
            lines[index] = f'{indent}version = "{version}"{newline}'
            replaced += 1

    if replaced != 1:
        raise ValueError(f"expected exactly one workspace.package version in {path}, found {replaced}")
    path.write_text("".join(lines), encoding="utf-8")


def write_lock_versions(
    path: Path,
    package_names: list[str],
    expected_current: str,
    version: str,
) -> None:
    parse_version(expected_current)
    parse_version(version)
    text = path.read_text(encoding="utf-8")
    parts = text.split("[[package]]")
    seen: set[str] = set()

    for index in range(1, len(parts)):
        block = parts[index]
        name_match = re.search(r'^name = "([^"]+)"$', block, re.MULTILINE)
        if name_match is None or name_match.group(1) not in package_names:
            continue
        name = name_match.group(1)
        version_match = re.search(r'^version = "([^"]+)"$', block, re.MULTILINE)
        if version_match is None:
            raise ValueError(f"workspace package has no lockfile version: {name}")
        if version_match.group(1) != expected_current:
            raise ValueError(
                f"lockfile version for {name} is {version_match.group(1)}, "
                f"expected {expected_current}"
            )
        parts[index] = re.sub(
            r'^version = "[^"]+"$',
            f'version = "{version}"',
            block,
            count=1,
            flags=re.MULTILINE,
        )
        seen.add(name)

    missing = set(package_names) - seen
    if missing:
        raise ValueError(f"workspace packages missing from lockfile: {sorted(missing)}")
    path.write_text("[[package]]".join(parts), encoding="utf-8")


def stable_tags() -> list[tuple[int, int, int]]:
    result = subprocess.run(
        ["git", "tag", "--list"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    versions: list[tuple[int, int, int]] = []
    for tag in result.stdout.splitlines():
        if not tag.startswith("v"):
            continue
        try:
            versions.append(parse_version(tag[1:]))
        except ValueError:
            continue
    return versions


def release_plan(
    workspace_version: str,
    tags: list[tuple[int, int, int]],
    release_date: date,
) -> dict[str, str]:
    parse_version(workspace_version)
    latest_tag = max(tags) if tags else None
    version = release_date_version(release_date, tags)
    version_tuple = parse_version(version)
    if latest_tag is not None and version_tuple <= latest_tag:
        raise ValueError(
            f"generated release tag v{version} would not be newer than the latest tag "
            f"v{format_version(latest_tag)}"
        )
    return {
        "workspace_version": workspace_version,
        "latest_tag_version": format_version(latest_tag) if latest_tag is not None else "",
        "release_date": release_date.isoformat(),
        "version": version,
        "tag": f"v{version}",
    }


def append_github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def self_test() -> None:
    assert parse_version("0.8.0") == (0, 8, 0)
    assert parse_release_date("2026-10-12") == date(2026, 10, 12)
    plan = release_plan("0.10.0", [(0, 9, 1), (0, 10, 0), (26, 10, 10)], date(2026, 10, 12))
    assert plan["latest_tag_version"] == "26.10.10"
    assert plan["version"] == "26.10.12"
    assert plan["tag"] == "v26.10.12"

    same_day_plan = release_plan("26.10.12", [(26, 10, 12)], date(2026, 10, 12))
    assert same_day_plan["version"] == "26.10.13"
    repeated_day_plan = release_plan(
        "26.10.12", [(26, 10, 12), (26, 10, 13)], date(2026, 10, 12)
    )
    assert repeated_day_plan["version"] == "26.10.14"

    try:
        release_plan("26.10.12", [(26, 11, 1)], date(2026, 10, 12))
    except ValueError as error:
        assert "would not be newer" in str(error)
    else:
        raise AssertionError("a release date behind the latest tag must be rejected")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest = root / "Cargo.toml"
        member = root / "app"
        member.mkdir()
        manifest.write_text(
            '[workspace]\nmembers = ["app"]\n\n[workspace.package]\nversion = "0.7.21"\n',
            encoding="utf-8",
        )
        (member / "Cargo.toml").write_text(
            '[package]\nname = "app"\nversion.workspace = true\n',
            encoding="utf-8",
        )
        lockfile = root / "Cargo.lock"
        lockfile.write_text(
            'version = 4\n\n[[package]]\nname = "app"\nversion = "0.7.21"\n',
            encoding="utf-8",
        )
        assert workspace_package_names(manifest) == ["app"]
        write_workspace_version(manifest, "26.10.12")
        write_lock_versions(lockfile, ["app"], "0.7.21", "26.10.12")
        assert read_workspace_version(manifest) == "26.10.12"
        assert 'version = "26.10.12"' in lockfile.read_text(encoding="utf-8")

    try:
        parse_version("01.2.3")
    except ValueError:
        pass
    else:
        raise AssertionError("leading-zero version components must be rejected")
    print("release_version self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--date",
        help="UTC release date in YYYY-MM-DD format (defaults to today's UTC date)",
    )
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return
    workspace_version = read_workspace_version(args.manifest)
    release_date = parse_release_date(args.date) if args.date else datetime.now(timezone.utc).date()
    plan = release_plan(workspace_version, stable_tags(), release_date)
    if args.write:
        package_names = workspace_package_names(args.manifest)
        write_workspace_version(args.manifest, plan["version"])
        write_lock_versions(
            args.lockfile,
            package_names,
            workspace_version,
            plan["version"],
        )
    if args.github_output is not None:
        append_github_output(args.github_output, plan)
    print(json.dumps(plan, sort_keys=True))


if __name__ == "__main__":
    main()
