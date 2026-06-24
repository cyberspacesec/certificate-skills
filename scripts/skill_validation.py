#!/usr/bin/env python3
"""Shared validation helpers for Anthropic-style skill packages."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from urllib.parse import unquote


ALLOWED_RESOURCE_DIRS = {"references", "scripts", "assets", "evals"}
CLAUDE_REQUIRED_SECTIONS = (
    "## When to Use",
    "## When NOT to Use",
    "## Instructions",
    "## Anti-Patterns",
)
EVAL_WORKSPACE_SUFFIX = "-workspace"
GENERATED_ARTIFACT_IGNORE_PATTERNS = ("*.skill", "*-workspace/", "/dist/")
PORTABLE_BODY_FORBIDDEN_TRIGGER_SECTIONS = ("## When to Use", "## When NOT to Use")
LEGACY_REF_RE = re.compile(r"certificate-hacker|cert-hacker")
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REFERENCE_TOC_RE = re.compile(r"^#{1,3} (Table of Contents|Contents)$", re.MULTILINE)
REFERENCE_TOC_MIN_LINES = 300
REFERENCE_USAGE_CUE = "Read when"
LINKED_BUNDLED_RESOURCE_DIRS = ("scripts", "assets")
TOOLS_RE = re.compile(r"\bcert_[A-Za-z0-9_]+\b")
CLAUDE_TOOLS_RE = re.compile(r"mcp__certificate-skills__(cert_[A-Za-z0-9_]+)")
XML_TAG_RE = re.compile(r"<[A-Za-z/][^>]*>")
RESERVED_NAME_PARTS = ("anthropic", "claude")
INSTALLATION_RE = re.compile(
    r"^(## Installation|### (Download Binary|Build from Source|Install Globally|"
    r"Verify Installation|Install as Go Module))$|see Installation section above",
    re.MULTILINE,
)


class ValidationFailure(SystemExit):
    """Raised when validation errors should stop a CLI command."""


def format_errors(label: str, errors: list[str]) -> str:
    details = "\n  - ".join(errors)
    return f"{label}:\n  - {details}"


def raise_for_errors(label: str, errors: list[str]) -> None:
    if errors:
        raise ValidationFailure(format_errors(label, errors))


def unquote_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def frontmatter_lines(skill_file: pathlib.Path) -> tuple[list[str], list[str]]:
    if not skill_file.is_file():
        return [], [f"missing SKILL.md: {skill_file}"]

    lines = skill_file.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        return [], [f"{skill_file}: missing opening YAML frontmatter delimiter"]

    try:
        close_index = lines[1:].index("---") + 1
    except ValueError:
        return [], [f"{skill_file}: missing closing YAML frontmatter delimiter"]

    return lines[1:close_index], []


def read_frontmatter(skill_file: pathlib.Path) -> tuple[dict[str, str], list[str]]:
    lines, errors = frontmatter_lines(skill_file)
    if errors:
        return {}, errors

    fields: dict[str, str] = {}
    for line in lines:
        if line.startswith("name:"):
            fields["name"] = unquote_scalar(line.split(":", 1)[1])
        elif line.startswith("description:"):
            fields["description"] = unquote_scalar(line.split(":", 1)[1])
        elif line.startswith("tools:"):
            fields["tools"] = line
        elif line.startswith("allowed-tools:"):
            fields["allowed-tools"] = line
    return fields, []


def iter_skill_dirs(skills_root: pathlib.Path, requested: list[str] | None = None) -> list[pathlib.Path]:
    if not skills_root.is_dir():
        raise ValidationFailure(f"missing skills root: {skills_root}")

    if requested:
        skill_dirs = [skills_root / name for name in requested]
    else:
        skill_dirs = sorted(path for path in skills_root.iterdir() if path.is_dir())

    missing = [path.name for path in skill_dirs if not (path / "SKILL.md").is_file()]
    if missing:
        raise ValidationFailure(f"missing SKILL.md for skill(s): {', '.join(sorted(missing))}")
    return skill_dirs


def skill_names(skills_root: pathlib.Path) -> set[str]:
    if not skills_root.is_dir():
        return set()
    return {
        path.name
        for path in skills_root.iterdir()
        if path.is_dir() and (path / "SKILL.md").is_file()
    }


def package_layout_errors(skill_dir: pathlib.Path) -> list[str]:
    errors = []
    for child in sorted(skill_dir.iterdir()):
        if child.name == "SKILL.md" and child.is_file():
            continue
        if child.is_dir() and child.name in ALLOWED_RESOURCE_DIRS:
            continue
        if child.is_dir():
            errors.append(
                f"{skill_dir}: unsupported bundled resource directory {child.name!r} "
                "(expected references, scripts, assets, or evals)"
            )
        else:
            errors.append(
                f"{skill_dir}: unsupported top-level skill package file {child.name!r} "
                "(expected SKILL.md or files under bundled resource directories)"
            )
    return errors


def frontmatter_errors(skill_dir: pathlib.Path, mode: str) -> list[str]:
    skill_file = skill_dir / "SKILL.md"
    fields, errors = read_frontmatter(skill_file)
    if errors:
        return errors

    line_count = len(skill_file.read_text(encoding="utf-8").splitlines())
    name = fields.get("name", "")
    description = fields.get("description", "")

    if line_count > 500:
        errors.append(
            f"{skill_file}: SKILL.md should stay lightweight "
            f"(found {line_count} lines, expected <= 500)"
        )

    if not NAME_RE.fullmatch(skill_dir.name):
        errors.append(f"{skill_file}: skill directory should be lowercase hyphenated")

    if not name:
        errors.append(f"{skill_file}: missing frontmatter name")
    else:
        if name != skill_dir.name:
            errors.append(
                f"{skill_file}: frontmatter name {name!r} does not match directory {skill_dir.name!r}"
            )
        if len(name) > 64:
            errors.append(
                f"{skill_file}: frontmatter name is too long "
                f"({len(name)} characters, expected <= 64)"
            )
        if not NAME_RE.fullmatch(name):
            errors.append(f"{skill_file}: frontmatter name should use lowercase letters, numbers, and hyphens")
        if XML_TAG_RE.search(name):
            errors.append(f"{skill_file}: frontmatter name must not contain XML tags")
        if any(part in name for part in RESERVED_NAME_PARTS):
            errors.append(f"{skill_file}: frontmatter name must not contain reserved words: anthropic, claude")

    if not description:
        errors.append(f"{skill_file}: missing frontmatter description")
    else:
        if len(description) > 1024:
            errors.append(
                f"{skill_file}: frontmatter description is too long "
                f"({len(description)} characters, expected <= 1024)"
            )
        if XML_TAG_RE.search(description):
            errors.append(f"{skill_file}: frontmatter description must not contain XML tags")
        if "Use when" not in description or "Triggers on mentions" not in description:
            errors.append(f"{skill_file}: frontmatter description should explain when the skill triggers")

    if mode == "portable":
        if "tools" not in fields:
            errors.append(f"{skill_file}: portable skill frontmatter should declare tools")
        if "allowed-tools" in fields:
            errors.append(f"{skill_file}: portable skill frontmatter should use tools, not allowed-tools")
    elif mode == "claude":
        frontmatter_text = "\n".join(frontmatter_lines(skill_file)[0])
        if "allowed-tools" not in fields:
            errors.append(f"{skill_file}: Claude Code skill frontmatter should declare allowed-tools")
        elif "mcp__certificate-skills__" not in frontmatter_text:
            errors.append(f"{skill_file}: allowed-tools should use the certificate-skills MCP server prefix")
        if "tools" in fields:
            errors.append(f"{skill_file}: Claude Code skill frontmatter should use allowed-tools, not tools")
    else:
        errors.append(f"{skill_file}: unknown validation mode {mode!r}")

    return errors


def validate_skill_creator_evals(
    evals: dict,
    label: str,
    expected_skill_name: str,
    min_cases: int,
    files_root: pathlib.Path | None,
    known_skill_names: set[str] | None = None,
    require_expected_skill_ref: bool = True,
) -> list[str]:
    errors = []
    if evals.get("skill_name") != expected_skill_name:
        errors.append(f"{label} skill_name must be {expected_skill_name}")

    eval_cases = evals.get("evals")
    if not isinstance(eval_cases, list) or len(eval_cases) < min_cases:
        errors.append(f"{label} evals must contain at least {min_cases} case(s)")
        return errors

    seen_ids: set[int] = set()
    for idx, case in enumerate(eval_cases):
        if not isinstance(case, dict):
            errors.append(f"{label} evals[{idx}] must be an object")
            continue

        case_id = case.get("id")
        if not isinstance(case_id, int):
            errors.append(f"{label} evals[{idx}].id must be an integer")
        elif case_id in seen_ids:
            errors.append(f"{label} duplicate eval case id: {case_id}")
        else:
            seen_ids.add(case_id)

        if not case.get("prompt"):
            errors.append(f"{label} evals[{idx}].prompt is required")

        expected_output = str(case.get("expected_output", ""))
        if not expected_output:
            errors.append(f"{label} evals[{idx}].expected_output is required")

        files = case.get("files", [])
        if not isinstance(files, list):
            errors.append(f"{label} evals[{idx}].files must be a list")
        elif not all(isinstance(item, str) for item in files):
            errors.append(f"{label} evals[{idx}].files entries must be strings")
        elif files_root is not None:
            root = files_root.resolve()
            for item in files:
                if not item:
                    errors.append(f"{label} evals[{idx}].files entries must be non-empty strings")
                    continue
                file_path = pathlib.PurePosixPath(item)
                if file_path.is_absolute() or ".." in file_path.parts:
                    errors.append(f"{label} evals[{idx}].files entry must stay inside the skill root: {item}")
                    continue
                resolved = (root / pathlib.Path(item)).resolve()
                try:
                    resolved.relative_to(root)
                except ValueError:
                    errors.append(f"{label} evals[{idx}].files entry escapes the skill root: {item}")
                    continue
                if not resolved.is_file():
                    errors.append(f"{label} evals[{idx}].files entry does not exist: {item}")

        expectations = case.get("expectations")
        if not isinstance(expectations, list) or not expectations:
            errors.append(f"{label} evals[{idx}].expectations must be a non-empty list")
        elif not all(isinstance(item, str) and item for item in expectations):
            errors.append(f"{label} evals[{idx}].expectations entries must be non-empty strings")
        else:
            expected_text = " ".join(expectations)
            if require_expected_skill_ref and expected_skill_name not in expected_text and expected_skill_name not in expected_output:
                errors.append(f"{label} evals[{idx}] should reference {expected_skill_name}")
            if known_skill_names and not any(
                skill_name in expected_text or skill_name in expected_output for skill_name in known_skill_names
            ):
                errors.append(f"{label} evals[{idx}] should reference at least one known skill")

    return errors


def read_json(path: pathlib.Path) -> tuple[dict | None, list[str]]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None, [f"missing file: {path}"]
    except json.JSONDecodeError as exc:
        return None, [f"{path}: invalid JSON: {exc}"]
    if not isinstance(data, dict):
        return None, [f"{path}: top-level JSON value must be an object"]
    return data, []


def repository_eval_errors(repo_root: pathlib.Path) -> list[str]:
    errors = []
    manifest_path = repo_root / "evals" / "skills-structure.json"
    evals_path = repo_root / "evals" / "evals.json"
    skills_root = repo_root / "skills"
    known_skill_names = skill_names(skills_root)

    manifest, manifest_errors = read_json(manifest_path)
    errors.extend(manifest_errors)
    if manifest:
        if manifest.get("suite") != "certificate-skills-structure":
            errors.append("suite must be certificate-skills-structure")
        if not isinstance(manifest.get("version"), int):
            errors.append("version must be an integer")
        cases = manifest.get("cases")
        if not isinstance(cases, list) or not cases:
            errors.append("cases must be a non-empty list")
        else:
            seen = set()
            for idx, case in enumerate(cases):
                if not isinstance(case, dict):
                    errors.append(f"cases[{idx}] must be an object")
                    continue
                case_id = case.get("id")
                if not case_id:
                    errors.append(f"cases[{idx}].id is required")
                elif case_id in seen:
                    errors.append(f"duplicate case id: {case_id}")
                else:
                    seen.add(case_id)
                if not case.get("prompt"):
                    errors.append(f"cases[{idx}].prompt is required")
                assertions = case.get("assertions")
                if not isinstance(assertions, list) or not assertions:
                    errors.append(f"cases[{idx}].assertions must be a non-empty list")

    root_evals, root_eval_errors = read_json(evals_path)
    errors.extend(root_eval_errors)
    if root_evals:
        errors.extend(
            validate_skill_creator_evals(
                root_evals,
                "evals/evals.json",
                "certificate-skills",
                min_cases=1,
                files_root=repo_root,
                known_skill_names=known_skill_names,
                require_expected_skill_ref=False,
            )
        )

    for skill_name in sorted(known_skill_names):
        skill_dir = skills_root / skill_name
        skill_evals_path = skill_dir / "evals" / "evals.json"
        skill_evals, skill_errors = read_json(skill_evals_path)
        if skill_errors:
            errors.extend(skill_errors)
            continue
        if skill_evals:
            errors.extend(
                validate_skill_creator_evals(
                    skill_evals,
                    str(skill_evals_path),
                    skill_name,
                    min_cases=2,
                    files_root=skill_dir,
                )
            )

    return errors


def skill_relative_files(skill_root: pathlib.Path, resource_dir: str) -> list[tuple[str, pathlib.Path]]:
    directory = skill_root / resource_dir
    if not directory.is_dir():
        return []
    files = []
    for resource_file in sorted(path for path in directory.rglob("*") if path.is_file()):
        target = resource_file.relative_to(skill_root).as_posix()
        files.append((target, resource_file))
    return files


def skill_file_link_errors(skill_file: pathlib.Path, require_reference_usage_cue: bool = False) -> list[str]:
    errors = []
    text = skill_file.read_text(encoding="utf-8")
    linked_targets = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in LINK_RE.finditer(line):
            raw_target = match.group(1).strip()
            target = raw_target.split("#", 1)[0]
            if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("/"):
                continue
            decoded_target = unquote(target)
            normalized_target = pathlib.PurePosixPath(decoded_target).as_posix()
            linked_targets.add(normalized_target)
            if require_reference_usage_cue and normalized_target.startswith("references/") and REFERENCE_USAGE_CUE not in line:
                errors.append(
                    f"{skill_file}:{line_no}: references link should explain when to read it "
                    f"with a {REFERENCE_USAGE_CUE!r} cue: {raw_target}"
                )
            resolved = (skill_file.parent / decoded_target).resolve()
            skill_root = skill_file.parent.resolve()
            try:
                resolved.relative_to(skill_root)
            except ValueError:
                errors.append(f"{skill_file}: link escapes skill package: {raw_target}")
                continue
            if not resolved.exists():
                errors.append(f"{skill_file}: missing linked resource: {raw_target}")

    references_dir = skill_file.parent / "references"
    if references_dir.is_dir():
        for target, reference_file in skill_relative_files(skill_file.parent, "references"):
            if target not in linked_targets:
                errors.append(f"{skill_file}: reference file is not linked from SKILL.md: {target}")
            reference_text = reference_file.read_text(encoding="utf-8")
            reference_lines = reference_text.splitlines()
            if len(reference_lines) > REFERENCE_TOC_MIN_LINES and not REFERENCE_TOC_RE.search(reference_text):
                errors.append(
                    f"{reference_file}: large reference files should include a table of contents "
                    f"(found {len(reference_lines)} lines, expected <= {REFERENCE_TOC_MIN_LINES} "
                    "without a Contents or Table of Contents heading)"
                )

    for resource_dir in LINKED_BUNDLED_RESOURCE_DIRS:
        for target, resource_file in skill_relative_files(skill_file.parent, resource_dir):
            if target not in linked_targets:
                errors.append(f"{skill_file}: bundled {resource_dir} file is not linked from SKILL.md: {target}")
            if resource_dir == "scripts" and not resource_file.stat().st_mode & 0o111:
                errors.append(f"{resource_file}: bundled script files should be executable")
    return errors


def skill_link_errors(repo_root: pathlib.Path) -> list[str]:
    errors = []
    portable_root = repo_root / "skills"
    for root in (repo_root / ".claude" / "skills", repo_root / "skills"):
        if not root.is_dir():
            continue
        for skill_file in sorted(root.glob("*/SKILL.md")):
            errors.extend(
                skill_file_link_errors(
                    skill_file,
                    require_reference_usage_cue=root == portable_root,
                )
            )
    return errors


def metadata_tools(skill_file: pathlib.Path, claude: bool = False) -> set[str]:
    lines, errors = frontmatter_lines(skill_file)
    if errors:
        return set()

    frontmatter = "\n".join(lines)
    if claude:
        return set(CLAUDE_TOOLS_RE.findall(frontmatter))
    return set(TOOLS_RE.findall(frontmatter))


def tool_metadata_parity_errors(repo_root: pathlib.Path) -> list[str]:
    errors = []
    portable_root = repo_root / "skills"
    claude_root = repo_root / ".claude" / "skills"
    for skill_dir in sorted(path for path in portable_root.iterdir() if path.is_dir()):
        portable_file = skill_dir / "SKILL.md"
        claude_file = claude_root / skill_dir.name / "SKILL.md"
        if not portable_file.is_file() or not claude_file.is_file():
            continue
        portable = metadata_tools(portable_file)
        claude = metadata_tools(claude_file, claude=True)
        if portable != claude:
            errors.append(
                f"{skill_dir.name}: portable tools {sorted(portable)} "
                f"do not match Claude Code allowed-tools {sorted(claude)}"
            )
    return errors


def claude_prompt_section_errors(skill_file: pathlib.Path) -> list[str]:
    text = skill_file.read_text(encoding="utf-8")
    lines = set(text.splitlines())
    return [
        f"{skill_file}: missing executable prompt section: {heading}"
        for heading in CLAUDE_REQUIRED_SECTIONS
        if heading not in lines
    ]


def get_description(skill_file: pathlib.Path) -> str:
    fields, errors = read_frontmatter(skill_file)
    if errors:
        return ""
    return fields.get("description", "")


def portable_prompt_errors(skill_dir: pathlib.Path, claude_root: pathlib.Path) -> list[str]:
    errors = []
    skill_file = skill_dir / "SKILL.md"
    text = skill_file.read_text(encoding="utf-8")
    lines = set(text.splitlines())
    for heading in PORTABLE_BODY_FORBIDDEN_TRIGGER_SECTIONS:
        if heading in lines:
            errors.append(
                f"{skill_file}: portable trigger guidance should stay in frontmatter description, "
                f"not body section {heading}"
            )
    if INSTALLATION_RE.search(text):
        errors.append(f"{skill_file}: portable SKILL.md should not duplicate repository installation instructions")

    claude_file = claude_root / skill_dir.name / "SKILL.md"
    if claude_file.is_file() and get_description(skill_file) != get_description(claude_file):
        errors.append(f"{skill_file}: portable description should match Claude Code skill trigger description")
    return errors


def root_parity_errors(portable_root: pathlib.Path, claude_root: pathlib.Path) -> list[str]:
    portable = {path.name for path in portable_root.iterdir() if path.is_dir()} if portable_root.is_dir() else set()
    claude = {path.name for path in claude_root.iterdir() if path.is_dir()} if claude_root.is_dir() else set()
    if portable == claude:
        return []

    only_claude = sorted(claude - portable)
    only_portable = sorted(portable - claude)
    errors = [".claude/skills and skills contain different skill directories"]
    if only_claude:
        errors.append(f"only in .claude/skills: {', '.join(only_claude)}")
    if only_portable:
        errors.append(f"only in skills: {', '.join(only_portable)}")
    return errors


def legacy_reference_errors(repo_root: pathlib.Path) -> list[str]:
    errors = []
    for relative in (".claude/skills", "skills", "evals", "README.md", "CLAUDE.md", "docs"):
        path = repo_root / relative
        if not path.exists():
            continue
        paths = [path] if path.is_file() else sorted(item for item in path.rglob("*") if item.is_file())
        for file_path in paths:
            try:
                text = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                if LEGACY_REF_RE.search(line):
                    errors.append(f"{file_path}:{line_no}: legacy certificate-hacker/cert-hacker reference remains")
    return errors


def packaging_script_errors(repo_root: pathlib.Path) -> list[str]:
    script = repo_root / "scripts" / "package-skills.py"
    errors = []
    if not script.is_file():
        return [f"missing skill packaging script: {script}"]
    if not script.stat().st_mode & 0o111:
        errors.append(f"{script} should be executable")

    result = subprocess.run(
        [sys.executable, str(script), "--check"],
        cwd=repo_root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        output = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
        errors.append(f"{script} --check failed:\n{output}")
    return errors


def tracked_repository_artifact_errors(repo_root: pathlib.Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return []

    errors = []
    for relative_path in result.stdout.splitlines():
        path = pathlib.PurePosixPath(relative_path)
        if path.suffix == ".skill":
            errors.append(f"{relative_path}: generated .skill archive should not be tracked")
        if any(part.endswith(EVAL_WORKSPACE_SUFFIX) for part in path.parts):
            errors.append(f"{relative_path}: skill eval workspaces should not be tracked")
    return errors


def gitignore_policy_errors(repo_root: pathlib.Path) -> list[str]:
    gitignore = repo_root / ".gitignore"
    if not gitignore.is_file():
        return [f"{gitignore}: missing .gitignore for generated skill artifacts"]

    patterns = {line.strip() for line in gitignore.read_text(encoding="utf-8").splitlines()}
    return [
        f"{gitignore}: should ignore generated skill artifact pattern {pattern!r}"
        for pattern in GENERATED_ARTIFACT_IGNORE_PATTERNS
        if pattern not in patterns
    ]


def validate_repository(repo_root: pathlib.Path, run_package_check: bool = True) -> list[str]:
    repo_root = repo_root.resolve()
    errors = []
    portable_root = repo_root / "skills"
    claude_root = repo_root / ".claude" / "skills"

    for root in (claude_root, portable_root):
        if not root.is_dir():
            errors.append(f"missing skills root: {root.relative_to(repo_root)}")
            continue
        mode = "portable" if root == portable_root else "claude"
        for skill_dir in sorted(path for path in root.iterdir() if path.is_dir()):
            errors.extend(frontmatter_errors(skill_dir, mode))
            errors.extend(package_layout_errors(skill_dir))
            if mode == "claude":
                errors.extend(claude_prompt_section_errors(skill_dir / "SKILL.md"))
            else:
                errors.extend(portable_prompt_errors(skill_dir, claude_root))

    if portable_root.is_dir() and claude_root.is_dir():
        errors.extend(root_parity_errors(portable_root, claude_root))
        errors.extend(tool_metadata_parity_errors(repo_root))

    errors.extend(legacy_reference_errors(repo_root))
    errors.extend(gitignore_policy_errors(repo_root))
    errors.extend(tracked_repository_artifact_errors(repo_root))
    errors.extend(repository_eval_errors(repo_root))
    errors.extend(skill_link_errors(repo_root))
    if run_package_check:
        errors.extend(packaging_script_errors(repo_root))

    return errors


def validate_portable_package(skill_dir: pathlib.Path) -> list[str]:
    errors = []
    errors.extend(package_layout_errors(skill_dir))
    errors.extend(frontmatter_errors(skill_dir, "portable"))
    errors.extend(skill_file_link_errors(skill_dir / "SKILL.md", require_reference_usage_cue=True))

    evals_file = skill_dir / "evals" / "evals.json"
    skill_evals, skill_errors = read_json(evals_file)
    if skill_errors:
        errors.extend(skill_errors)
    elif skill_evals:
        errors.extend(
            validate_skill_creator_evals(
                skill_evals,
                str(evals_file),
                skill_dir.name,
                min_cases=2,
                files_root=skill_dir,
            )
        )
    return errors


def validate_portable_packages(skills_root: pathlib.Path, requested: list[str] | None = None) -> list[pathlib.Path]:
    skill_dirs = iter_skill_dirs(skills_root, requested)
    all_errors = []
    for skill_dir in skill_dirs:
        all_errors.extend(validate_portable_package(skill_dir))
    raise_for_errors("invalid portable skill package(s)", all_errors)
    return skill_dirs


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Anthropic-style skill repository structure.")
    parser.add_argument("--repo-root", default=".", help="Repository root to validate.")
    parser.add_argument(
        "--no-package-check",
        action="store_true",
        help="Skip invoking scripts/package-skills.py --check.",
    )
    args = parser.parse_args()

    errors = validate_repository(pathlib.Path(args.repo_root), run_package_check=not args.no_package_check)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("Skill structure validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
