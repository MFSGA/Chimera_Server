#!/usr/bin/env python3
"""Compute and optionally apply the next stable workspace release version."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path

SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
WORKSPACE_HEADER = "[workspace.package]"


def parse_version(value: str) -> tuple[int, int, int]:
    match = SEMVER_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"expected stable SemVer X.Y.Z, got {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def format_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def bump_version(version: tuple[int, int, int], bump: str) -> tuple[int, int, int]:
    major, minor, patch = version
    if bump == "patch":
        return major, minor, patch + 1
    if bump == "minor":
        return major, minor + 1, 0
    if bump == "major":
        return major + 1, 0, 0
    raise ValueError(f"unsupported SemVer bump: {bump!r}")


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


def release_plan(workspace_version: str, tags: list[tuple[int, int, int]], bump: str) -> dict[str, str]:
    workspace = parse_version(workspace_version)
    latest_tag = max(tags) if tags else None
    base = max(workspace, latest_tag) if latest_tag is not None else workspace
    next_version = bump_version(base, bump)
    return {
        "workspace_version": workspace_version,
        "latest_tag_version": format_version(latest_tag) if latest_tag is not None else "",
        "base_version": format_version(base),
        "version": format_version(next_version),
        "tag": f"v{format_version(next_version)}",
    }


def append_github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def self_test() -> None:
    assert parse_version("0.8.0") == (0, 8, 0)
    assert bump_version((0, 8, 0), "patch") == (0, 8, 1)
    assert bump_version((0, 8, 0), "minor") == (0, 9, 0)
    assert bump_version((0, 8, 0), "major") == (1, 0, 0)
    plan = release_plan("0.7.21", [(0, 7, 21), (0, 8, 0)], "patch")
    assert plan["base_version"] == "0.8.0"
    assert plan["version"] == "0.8.1"

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
        write_workspace_version(manifest, "0.8.1")
        write_lock_versions(lockfile, ["app"], "0.7.21", "0.8.1")
        assert read_workspace_version(manifest) == "0.8.1"
        assert 'version = "0.8.1"' in lockfile.read_text(encoding="utf-8")

    try:
        parse_version("01.2.3")
    except ValueError:
        pass
    else:
        raise AssertionError("leading-zero SemVer must be rejected")
    print("release_version self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bump", choices=("patch", "minor", "major"))
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return
    if args.bump is None:
        parser.error("--bump is required unless --self-test is used")

    workspace_version = read_workspace_version(args.manifest)
    plan = release_plan(workspace_version, stable_tags(), args.bump)
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
