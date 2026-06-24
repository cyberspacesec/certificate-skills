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
EVAL_MANIFEST_KEYS = {"skill_name", "evals"}
EVAL_CASE_KEYS = {"id", "prompt", "expected_output", "files", "expectations"}
GRADING_EXPECTATION_KEYS = {"text", "passed", "evidence"}
BENCHMARK_RUN_RESULT_KEYS = {
    "pass_rate",
    "passed",
    "failed",
    "total",
    "time_seconds",
    "tokens",
    "tool_calls",
    "errors",
}
HISTORY_GRADING_RESULTS = {"baseline", "won", "lost", "tie"}
EVAL_PROMPT_CONTROL_PHRASES = (
    "Handle a focused",
    "do not switch to a broader certificate audit",
)
GENERATED_ARTIFACT_IGNORE_PATTERNS = (
    "*.skill",
    "*.test",
    "*-workspace/",
    "/benchmarks/",
    "/bin/",
    "/dist/",
    "coverage.html",
    "coverage.out",
)
DISALLOWED_PACKAGED_ARTIFACT_NAMES = {".DS_Store", "Thumbs.db", "__pycache__"}
DISALLOWED_PACKAGED_ARTIFACT_SUFFIXES = {".pyc", ".pyo"}
DESCRIPTION_MAX_WORDS = 100
PORTABLE_FRONTMATTER_KEYS = {"name", "description", "tools", "compatibility"}
CLAUDE_FRONTMATTER_KEYS = {"name", "description", "allowed-tools", "compatibility"}
DISALLOWED_SKILL_CONTENT_PATTERNS = (
    (re.compile(r"\brm\s+-rf\s+/(?:\s|$)"), "destructive root deletion command"),
    (re.compile(r"\bmkfs(?:\.[A-Za-z0-9_+-]+)?\s+"), "filesystem formatting command"),
    (
        re.compile(r"\bdd\b[^\n]*\bof=/dev/(?:sd|vd|xvd|nvme|disk|mapper)"),
        "raw block-device overwrite command",
    ),
    (
        re.compile(r"\b(?:nc|ncat)\b[^\n]*(?:\s-e\s|--exec\b|--sh-exec\b)"),
        "netcat exec shell command",
    ),
    (re.compile(r"(?:\bbash\s+-i\b[^\n]*/dev/tcp|/dev/tcp/)"), "reverse shell TCP redirection"),
    (re.compile(r"\bcurl\b[^\n]*\|\s*(?:sh|bash)\b"), "remote shell installer command"),
    (re.compile(r"\bwget\b[^\n]*\|\s*(?:sh|bash)\b"), "remote shell installer command"),
)
PORTABLE_BODY_FORBIDDEN_TRIGGER_SECTIONS = ("## When to Use", "## When NOT to Use")
LEGACY_REF_RE = re.compile(r"certificate-hacker|cert-hacker")
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
MARKDOWN_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REFERENCE_TOC_RE = re.compile(r"^#{1,3} (Table of Contents|Contents)$", re.MULTILINE)
REFERENCE_TOC_MIN_LINES = 300
REFERENCE_USAGE_CUE = "Read when"
LINKED_BUNDLED_RESOURCE_DIRS = ("scripts", "assets")
FRONTMATTER_KEY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*):")
MCP_TOOL_PREFIX = "mcp__certificate-skills__"
XML_TAG_RE = re.compile(r"<[A-Za-z/][^>]*>")
RESERVED_NAME_PARTS = ("anthropic", "claude")
INSTALLATION_RE = re.compile(
    r"^(## Installation|### (Download Binary|Build from Source|Install Globally|"
    r"Verify Installation|Install as Go Module))$|see Installation section above",
    re.MULTILINE,
)
INSTALLATION_NOTE_RE = re.compile(r"\bInstall cert-skills first\b")


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


def body_lines(skill_file: pathlib.Path) -> tuple[list[str], list[str]]:
    if not skill_file.is_file():
        return [], [f"missing SKILL.md: {skill_file}"]

    lines = skill_file.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        return [], [f"{skill_file}: missing opening YAML frontmatter delimiter"]

    try:
        close_index = lines[1:].index("---") + 1
    except ValueError:
        return [], [f"{skill_file}: missing closing YAML frontmatter delimiter"]
    return lines[close_index + 1 :], []


def markdown_lines_outside_fences(lines: list[str]) -> list[str]:
    content = []
    fence_char = ""
    fence_len = 0
    for line in lines:
        match = MARKDOWN_FENCE_RE.match(line)
        if match:
            marker = match.group(1)
            char = marker[0]
            if not fence_char:
                fence_char = char
                fence_len = len(marker)
                continue
            if char == fence_char and len(marker) >= fence_len and not line[match.end() :].strip():
                fence_char = ""
                fence_len = 0
                continue
        if not fence_char:
            content.append(line)
    return content


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


def frontmatter_list_values(lines: list[str], key: str) -> tuple[list[str], list[str]]:
    values = []
    errors = []
    in_list = False
    key_seen = False
    for line in lines:
        key_match = FRONTMATTER_KEY_RE.match(line)
        if key_match:
            if key_match.group(1) == key:
                key_seen = True
                inline_value = line.split(":", 1)[1].strip()
                if inline_value:
                    try:
                        parsed = json.loads(inline_value)
                    except json.JSONDecodeError:
                        errors.append(f"{key}: inline frontmatter list should use JSON-style string list syntax")
                    else:
                        if isinstance(parsed, list) and all(isinstance(item, str) for item in parsed):
                            values.extend(parsed)
                        else:
                            errors.append(f"{key}: inline frontmatter list should contain only strings")
                    break
                in_list = True
            elif in_list:
                break
            continue
        if not in_list:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" "):
            errors.append(f"{key}: frontmatter list item should be indented: {line}")
            continue
        list_match = re.match(r"^\s*-\s+(.+)$", line)
        if not list_match:
            errors.append(f"{key}: frontmatter list item should use '- value' syntax: {line}")
            continue
        values.append(unquote_scalar(list_match.group(1)))
    if key_seen and not values:
        errors.append(f"{key}: frontmatter list should contain at least one item")
    return values, errors


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

    evals_dir = skill_dir / "evals"
    if evals_dir.is_dir():
        for child in sorted(evals_dir.iterdir()):
            if child.name == "evals.json" and child.is_file():
                continue
            if child.name == "files" and child.is_dir():
                continue
            if child.is_dir():
                errors.append(
                    f"{skill_dir}: unsupported evals directory {child.name!r} "
                    "(expected evals.json or files/)"
                )
            else:
                errors.append(
                    f"{skill_dir}: unsupported evals file {child.name!r} "
                    "(expected evals.json or files/)"
                )
    return errors


def frontmatter_errors(skill_dir: pathlib.Path, mode: str) -> list[str]:
    skill_file = skill_dir / "SKILL.md"
    fields, errors = read_frontmatter(skill_file)
    if errors:
        return errors

    lines = frontmatter_lines(skill_file)[0]
    body_text = "\n".join(body_lines(skill_file)[0])
    line_count = len(skill_file.read_text(encoding="utf-8").splitlines())
    name = fields.get("name", "")
    description = fields.get("description", "")

    if mode == "portable":
        allowed_keys = PORTABLE_FRONTMATTER_KEYS
    elif mode == "claude":
        allowed_keys = CLAUDE_FRONTMATTER_KEYS
    else:
        allowed_keys = set()
    seen_keys: set[str] = set()
    for line in lines:
        match = FRONTMATTER_KEY_RE.match(line)
        if not match:
            continue
        key = match.group(1)
        if key in seen_keys:
            errors.append(f"{skill_file}: duplicate frontmatter key: {key}")
        else:
            seen_keys.add(key)
        if key not in allowed_keys:
            errors.append(f"{skill_file}: unsupported frontmatter key: {key}")

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
        word_count = len(re.findall(r"\S+", description))
        if word_count > DESCRIPTION_MAX_WORDS:
            errors.append(
                f"{skill_file}: frontmatter description should stay concise "
                f"({word_count} words, expected <= {DESCRIPTION_MAX_WORDS})"
            )
        if XML_TAG_RE.search(description):
            errors.append(f"{skill_file}: frontmatter description must not contain XML tags")
        if "Use when" not in description or "Triggers on mentions" not in description:
            errors.append(f"{skill_file}: frontmatter description should explain when the skill triggers")

    if mode == "portable":
        if "tools" not in fields:
            errors.append(f"{skill_file}: portable skill frontmatter should declare tools")
        else:
            tools, tool_errors = frontmatter_list_values(lines, "tools")
            for error in tool_errors:
                errors.append(f"{skill_file}: {error}")
            for tool in tools:
                if not re.fullmatch(r"cert_[A-Za-z0-9_]+", tool):
                    errors.append(f"{skill_file}: portable tools entry should be an unprefixed cert_* tool: {tool}")
                elif tool not in body_text:
                    errors.append(f"{skill_file}: portable tools entry should be referenced in Markdown instructions: {tool}")
        if "allowed-tools" in fields:
            errors.append(f"{skill_file}: portable skill frontmatter should use tools, not allowed-tools")
    elif mode == "claude":
        frontmatter_text = "\n".join(frontmatter_lines(skill_file)[0])
        if "allowed-tools" not in fields:
            errors.append(f"{skill_file}: Claude Code skill frontmatter should declare allowed-tools")
        else:
            tools, tool_errors = frontmatter_list_values(lines, "allowed-tools")
            for error in tool_errors:
                errors.append(f"{skill_file}: {error}")
            for tool in tools:
                if not re.fullmatch(rf"{MCP_TOOL_PREFIX}cert_[A-Za-z0-9_]+", tool):
                    errors.append(
                        f"{skill_file}: allowed-tools entry should use the certificate-skills MCP prefix: {tool}"
                    )
                elif tool.removeprefix(MCP_TOOL_PREFIX) not in body_text:
                    errors.append(
                        f"{skill_file}: allowed-tools entry should be referenced in Markdown instructions: {tool}"
                    )
            if MCP_TOOL_PREFIX not in frontmatter_text:
                errors.append(f"{skill_file}: allowed-tools should use the certificate-skills MCP server prefix")
        if "tools" in fields:
            errors.append(f"{skill_file}: Claude Code skill frontmatter should use allowed-tools, not tools")
    else:
        errors.append(f"{skill_file}: unknown validation mode {mode!r}")

    errors.extend(markdown_instruction_errors(skill_file))
    return errors


def markdown_instruction_errors(skill_file: pathlib.Path) -> list[str]:
    lines, errors = body_lines(skill_file)
    if errors:
        return []

    content = [line for line in markdown_lines_outside_fences(lines) if line.strip()]
    if not content:
        return [f"{skill_file}: SKILL.md should include Markdown instructions after frontmatter"]
    if not content[0].startswith("# "):
        return [f"{skill_file}: SKILL.md instructions should start with an H1 heading"]
    h1_headings = [line for line in content if line.startswith("# ")]
    if len(h1_headings) != 1:
        return [f"{skill_file}: SKILL.md instructions should contain exactly one H1 heading"]
    if not any(line.startswith("## ") for line in content[1:]):
        return [f"{skill_file}: SKILL.md instructions should include at least one H2 section"]
    return []


def validate_skill_creator_evals(
    evals: dict,
    label: str,
    expected_skill_name: str,
    min_cases: int,
    max_cases: int | None,
    files_root: pathlib.Path | None,
    required_files_prefix: str | None = None,
    known_skill_names: set[str] | None = None,
    require_expected_skill_ref: bool = True,
) -> list[str]:
    errors = []
    unknown_manifest_keys = sorted(set(evals) - EVAL_MANIFEST_KEYS)
    if unknown_manifest_keys:
        errors.append(f"{label} contains unknown top-level key(s): {', '.join(unknown_manifest_keys)}")

    if evals.get("skill_name") != expected_skill_name:
        errors.append(f"{label} skill_name must be {expected_skill_name}")
    if not isinstance(evals.get("skill_name"), str):
        errors.append(f"{label} skill_name must be a string")

    eval_cases = evals.get("evals")
    if not isinstance(eval_cases, list) or len(eval_cases) < min_cases:
        errors.append(f"{label} evals must contain at least {min_cases} case(s)")
        return errors
    if max_cases is not None and len(eval_cases) > max_cases:
        errors.append(f"{label} evals should contain at most {max_cases} case(s)")

    seen_ids: set[int] = set()
    for idx, case in enumerate(eval_cases):
        if not isinstance(case, dict):
            errors.append(f"{label} evals[{idx}] must be an object")
            continue

        unknown_case_keys = sorted(set(case) - EVAL_CASE_KEYS)
        if unknown_case_keys:
            errors.append(f"{label} evals[{idx}] contains unknown key(s): {', '.join(unknown_case_keys)}")

        case_id = case.get("id")
        if not isinstance(case_id, int) or isinstance(case_id, bool):
            errors.append(f"{label} evals[{idx}].id must be an integer")
        elif case_id in seen_ids:
            errors.append(f"{label} duplicate eval case id: {case_id}")
        else:
            seen_ids.add(case_id)

        prompt = case.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            errors.append(f"{label} evals[{idx}].prompt is required")
        elif any(phrase in prompt for phrase in EVAL_PROMPT_CONTROL_PHRASES):
            errors.append(f"{label} evals[{idx}].prompt should read like a realistic user request")

        expected_output = case.get("expected_output")
        if not isinstance(expected_output, str) or not expected_output:
            errors.append(f"{label} evals[{idx}].expected_output is required")
            expected_output = ""

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
                if required_files_prefix and not file_path.as_posix().startswith(required_files_prefix):
                    errors.append(
                        f"{label} evals[{idx}].files entry should live under {required_files_prefix}: {item}"
                    )
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

    if len(seen_ids) == len(eval_cases):
        expected_ids = set(range(1, len(eval_cases) + 1))
        if seen_ids != expected_ids:
            errors.append(f"{label} eval ids should be consecutive integers starting at 1")

    return errors


def eval_fixture_usage_errors(skill_dir: pathlib.Path, evals: dict, label: str) -> list[str]:
    fixtures_dir = skill_dir / "evals" / "files"
    if not fixtures_dir.is_dir():
        return []

    referenced: set[str] = set()
    eval_cases = evals.get("evals")
    if isinstance(eval_cases, list):
        for case in eval_cases:
            if not isinstance(case, dict):
                continue
            files = case.get("files", [])
            if isinstance(files, list):
                referenced.update(item for item in files if isinstance(item, str))

    errors = []
    for fixture in sorted(path for path in fixtures_dir.rglob("*") if path.is_file()):
        target = fixture.relative_to(skill_dir).as_posix()
        if target not in referenced:
            errors.append(f"{label}: eval fixture is not referenced from evals[].files: {target}")
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


def read_json_array(path: pathlib.Path) -> tuple[list | None, list[str]]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None, [f"missing file: {path}"]
    except json.JSONDecodeError as exc:
        return None, [f"{path}: invalid JSON: {exc}"]
    if not isinstance(data, list):
        return None, [f"{path}: top-level JSON value must be an array"]
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
                max_cases=None,
                files_root=repo_root,
                required_files_prefix=None,
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
                    max_cases=3,
                    files_root=skill_dir,
                    required_files_prefix="evals/files/",
                )
            )
            errors.extend(eval_fixture_usage_errors(skill_dir, skill_evals, str(skill_evals_path)))

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

    if claude:
        return {
            value.removeprefix(MCP_TOOL_PREFIX)
            for value in frontmatter_list_values(lines, "allowed-tools")[0]
        }
    return set(frontmatter_list_values(lines, "tools")[0])


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
    lines = set(markdown_lines_outside_fences(text.splitlines()))
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


def portable_body_policy_errors(skill_dir: pathlib.Path) -> list[str]:
    errors = []
    skill_file = skill_dir / "SKILL.md"
    text = skill_file.read_text(encoding="utf-8")
    lines = set(markdown_lines_outside_fences(text.splitlines()))
    for heading in PORTABLE_BODY_FORBIDDEN_TRIGGER_SECTIONS:
        if heading in lines:
            errors.append(
                f"{skill_file}: portable trigger guidance should stay in frontmatter description, "
                f"not body section {heading}"
            )
    if INSTALLATION_RE.search(text) or INSTALLATION_NOTE_RE.search(text):
        errors.append(f"{skill_file}: portable SKILL.md should not duplicate repository installation instructions")
    return errors


def portable_prompt_errors(skill_dir: pathlib.Path, claude_root: pathlib.Path) -> list[str]:
    errors = portable_body_policy_errors(skill_dir)
    skill_file = skill_dir / "SKILL.md"

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


def skill_package_safety_errors(skill_dir: pathlib.Path) -> list[str]:
    errors = []
    if not skill_dir.is_dir():
        return errors

    for file_path in sorted(path for path in skill_dir.rglob("*") if path.is_file()):
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern, label in DISALLOWED_SKILL_CONTENT_PATTERNS:
                if pattern.search(line):
                    errors.append(f"{file_path}:{line_no}: disallowed skill content: {label}")
    return errors


def packaged_artifact_errors(skill_dir: pathlib.Path) -> list[str]:
    errors = []
    if not skill_dir.is_dir():
        return errors

    for path in sorted(skill_dir.rglob("*")):
        relative = path.relative_to(skill_dir)
        relative_path = relative.as_posix()
        if any(part in DISALLOWED_PACKAGED_ARTIFACT_NAMES for part in relative.parts):
            errors.append(f"{skill_dir}: generated/cache artifact should not be bundled: {relative_path}")
        elif path.is_file() and path.suffix in DISALLOWED_PACKAGED_ARTIFACT_SUFFIXES:
            errors.append(f"{skill_dir}: generated/cache artifact should not be bundled: {relative_path}")
        elif path.is_file() and path.name.endswith("~"):
            errors.append(f"{skill_dir}: backup artifact should not be bundled: {relative_path}")
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
        if path.suffix == ".test":
            errors.append(f"{relative_path}: generated Go test binary should not be tracked")
        if path.parts and path.parts[0] == "bin":
            errors.append(f"{relative_path}: generated binary output should not be tracked")
        if path.parts and path.parts[0] == "benchmarks":
            errors.append(f"{relative_path}: generated skill benchmark output should not be tracked")
        if path.name in {"coverage.html", "coverage.out"}:
            errors.append(f"{relative_path}: generated coverage report should not be tracked")
        if any(part.endswith(EVAL_WORKSPACE_SUFFIX) for part in path.parts):
            errors.append(f"{relative_path}: skill eval workspaces should not be tracked")
    return errors


def validate_grading_output_schema(path: pathlib.Path) -> list[str]:
    grading, errors = read_json(path)
    if errors:
        return errors
    if not grading:
        return []

    expectations = grading.get("expectations")
    if not isinstance(expectations, list):
        return [f"{path}: grading.json expectations must be a list"]

    errors = []
    for idx, expectation in enumerate(expectations):
        if not isinstance(expectation, dict):
            errors.append(f"{path}: expectations[{idx}] must be an object")
            continue
        keys = set(expectation)
        if keys != GRADING_EXPECTATION_KEYS:
            expected = ", ".join(sorted(GRADING_EXPECTATION_KEYS))
            found = ", ".join(sorted(keys))
            errors.append(f"{path}: expectations[{idx}] must use exactly {expected} fields, found {found}")
            continue
        if not isinstance(expectation.get("text"), str) or not expectation["text"]:
            errors.append(f"{path}: expectations[{idx}].text must be a non-empty string")
        if not isinstance(expectation.get("passed"), bool):
            errors.append(f"{path}: expectations[{idx}].passed must be a boolean")
        if not isinstance(expectation.get("evidence"), str):
            errors.append(f"{path}: expectations[{idx}].evidence must be a string")
    return errors


def validate_benchmark_output_schema(path: pathlib.Path) -> list[str]:
    benchmark, errors = read_json(path)
    if errors:
        return errors
    if not benchmark:
        return []

    errors = []
    metadata = benchmark.get("metadata")
    if not isinstance(metadata, dict):
        errors.append(f"{path}: benchmark.json metadata must be an object")
    else:
        if not isinstance(metadata.get("skill_name"), str) or not metadata["skill_name"]:
            errors.append(f"{path}: metadata.skill_name must be a non-empty string")
        if not isinstance(metadata.get("evals_run"), list):
            errors.append(f"{path}: metadata.evals_run must be a list")
        if not isinstance(metadata.get("runs_per_configuration"), int) or isinstance(
            metadata.get("runs_per_configuration"), bool
        ):
            errors.append(f"{path}: metadata.runs_per_configuration must be an integer")

    runs = benchmark.get("runs")
    if not isinstance(runs, list):
        errors.append(f"{path}: benchmark.json runs must be a list")
    else:
        for idx, run in enumerate(runs):
            if not isinstance(run, dict):
                errors.append(f"{path}: runs[{idx}] must be an object")
                continue
            if "config" in run:
                errors.append(f"{path}: runs[{idx}] must use configuration, not config")
            for misplaced_key in ("pass_rate", "time_seconds", "tokens"):
                if misplaced_key in run:
                    errors.append(f"{path}: runs[{idx}].{misplaced_key} must be nested under result")
            if not isinstance(run.get("eval_id"), int) or isinstance(run.get("eval_id"), bool):
                errors.append(f"{path}: runs[{idx}].eval_id must be an integer")
            if not isinstance(run.get("eval_name"), str) or not run["eval_name"]:
                errors.append(f"{path}: runs[{idx}].eval_name must be a non-empty string")
            if run.get("configuration") not in {"with_skill", "without_skill"}:
                errors.append(f"{path}: runs[{idx}].configuration must be with_skill or without_skill")
            if not isinstance(run.get("run_number"), int) or isinstance(run.get("run_number"), bool):
                errors.append(f"{path}: runs[{idx}].run_number must be an integer")

            result = run.get("result")
            if not isinstance(result, dict):
                errors.append(f"{path}: runs[{idx}].result must be an object")
            else:
                missing = sorted({"pass_rate", "passed", "total", "time_seconds", "tokens", "errors"} - set(result))
                if missing:
                    errors.append(f"{path}: runs[{idx}].result missing key(s): {', '.join(missing)}")
                unknown = sorted(set(result) - BENCHMARK_RUN_RESULT_KEYS)
                if unknown:
                    errors.append(f"{path}: runs[{idx}].result contains unknown key(s): {', '.join(unknown)}")

            expectations = run.get("expectations", [])
            if expectations is not None:
                if not isinstance(expectations, list):
                    errors.append(f"{path}: runs[{idx}].expectations must be a list")
                else:
                    for expectation_idx, expectation in enumerate(expectations):
                        if not isinstance(expectation, dict):
                            errors.append(f"{path}: runs[{idx}].expectations[{expectation_idx}] must be an object")
                            continue
                        missing = sorted(GRADING_EXPECTATION_KEYS - set(expectation))
                        if missing:
                            errors.append(
                                f"{path}: runs[{idx}].expectations[{expectation_idx}] missing key(s): "
                                f"{', '.join(missing)}"
                            )

    run_summary = benchmark.get("run_summary")
    if not isinstance(run_summary, dict):
        errors.append(f"{path}: benchmark.json run_summary must be an object")
    return errors


def validate_feedback_output_schema(path: pathlib.Path) -> list[str]:
    feedback, errors = read_json(path)
    if errors:
        return errors
    if not feedback:
        return []

    errors = []
    if feedback.get("status") != "complete":
        errors.append(f"{path}: feedback status must be complete")
    reviews = feedback.get("reviews")
    if not isinstance(reviews, list):
        errors.append(f"{path}: feedback reviews must be a list")
    else:
        for idx, review in enumerate(reviews):
            if not isinstance(review, dict):
                errors.append(f"{path}: reviews[{idx}] must be an object")
                continue
            for key in ("run_id", "feedback", "timestamp"):
                if not isinstance(review.get(key), str):
                    errors.append(f"{path}: reviews[{idx}].{key} must be a string")
    return errors


def validate_eval_metadata_output_schema(path: pathlib.Path) -> list[str]:
    metadata, errors = read_json(path)
    if errors:
        return errors
    if not metadata:
        return []

    errors = []
    if not isinstance(metadata.get("eval_id"), int) or isinstance(metadata.get("eval_id"), bool):
        errors.append(f"{path}: eval_metadata eval_id must be an integer")
    if not isinstance(metadata.get("eval_name"), str) or not metadata["eval_name"]:
        errors.append(f"{path}: eval_metadata eval_name must be a non-empty string")
    if not isinstance(metadata.get("prompt"), str) or not metadata["prompt"]:
        errors.append(f"{path}: eval_metadata prompt must be a non-empty string")
    assertions = metadata.get("assertions")
    if not isinstance(assertions, list):
        errors.append(f"{path}: eval_metadata assertions must be a list")
    elif not all(isinstance(item, str) for item in assertions):
        errors.append(f"{path}: eval_metadata assertions entries must be strings")
    return errors


def validate_metrics_output_schema(path: pathlib.Path) -> list[str]:
    metrics, errors = read_json(path)
    if errors:
        return errors
    if not metrics:
        return []

    errors = []
    tool_calls = metrics.get("tool_calls")
    if not isinstance(tool_calls, dict):
        errors.append(f"{path}: metrics tool_calls must be an object")
    elif not all(isinstance(key, str) and isinstance(value, int) for key, value in tool_calls.items()):
        errors.append(f"{path}: metrics tool_calls entries must map tool names to integer counts")

    int_fields = (
        "total_tool_calls",
        "total_steps",
        "errors_encountered",
        "output_chars",
        "transcript_chars",
    )
    for field in int_fields:
        if not isinstance(metrics.get(field), int) or isinstance(metrics.get(field), bool):
            errors.append(f"{path}: metrics {field} must be an integer")

    files_created = metrics.get("files_created")
    if not isinstance(files_created, list):
        errors.append(f"{path}: metrics files_created must be a list")
    elif not all(isinstance(item, str) for item in files_created):
        errors.append(f"{path}: metrics files_created entries must be strings")
    return errors


def validate_timing_output_schema(path: pathlib.Path) -> list[str]:
    timing, errors = read_json(path)
    if errors:
        return errors
    if not timing:
        return []

    errors = []
    if not isinstance(timing.get("total_tokens"), int) or isinstance(timing.get("total_tokens"), bool):
        errors.append(f"{path}: timing total_tokens must be an integer")
    if not isinstance(timing.get("duration_ms"), int) or isinstance(timing.get("duration_ms"), bool):
        errors.append(f"{path}: timing duration_ms must be an integer")
    if not isinstance(timing.get("total_duration_seconds"), (int, float)) or isinstance(
        timing.get("total_duration_seconds"), bool
    ):
        errors.append(f"{path}: timing total_duration_seconds must be a number")

    timestamp_fields = ("executor_start", "executor_end", "grader_start", "grader_end")
    for field in timestamp_fields:
        if field in timing and not isinstance(timing.get(field), str):
            errors.append(f"{path}: timing {field} must be a string when present")

    duration_fields = ("executor_duration_seconds", "grader_duration_seconds")
    for field in duration_fields:
        if field in timing and (
            not isinstance(timing.get(field), (int, float)) or isinstance(timing.get(field), bool)
        ):
            errors.append(f"{path}: timing {field} must be a number when present")
    return errors


def validate_history_output_schema(path: pathlib.Path) -> list[str]:
    history, errors = read_json(path)
    if errors:
        return errors
    if not history:
        return []

    errors = []
    if not isinstance(history.get("started_at"), str) or not history["started_at"]:
        errors.append(f"{path}: history started_at must be a non-empty string")
    if not isinstance(history.get("skill_name"), str) or not history["skill_name"]:
        errors.append(f"{path}: history skill_name must be a non-empty string")
    if not isinstance(history.get("current_best"), str) or not history["current_best"]:
        errors.append(f"{path}: history current_best must be a non-empty string")

    iterations = history.get("iterations")
    if not isinstance(iterations, list):
        errors.append(f"{path}: history iterations must be a list")
    else:
        for idx, iteration in enumerate(iterations):
            if not isinstance(iteration, dict):
                errors.append(f"{path}: iterations[{idx}] must be an object")
                continue
            if not isinstance(iteration.get("version"), str) or not iteration["version"]:
                errors.append(f"{path}: iterations[{idx}].version must be a non-empty string")
            parent = iteration.get("parent")
            if parent is not None and not isinstance(parent, str):
                errors.append(f"{path}: iterations[{idx}].parent must be a string or null")
            if not isinstance(iteration.get("expectation_pass_rate"), (int, float)) or isinstance(
                iteration.get("expectation_pass_rate"), bool
            ):
                errors.append(f"{path}: iterations[{idx}].expectation_pass_rate must be a number")
            if iteration.get("grading_result") not in HISTORY_GRADING_RESULTS:
                errors.append(f"{path}: iterations[{idx}].grading_result must be baseline, won, lost, or tie")
            if not isinstance(iteration.get("is_current_best"), bool):
                errors.append(f"{path}: iterations[{idx}].is_current_best must be a boolean")
    return errors


def validate_comparison_output_schema(path: pathlib.Path) -> list[str]:
    comparison, errors = read_json(path)
    if errors:
        return errors
    if not comparison:
        return []

    errors = []
    if not isinstance(comparison.get("winner"), str) or not comparison["winner"]:
        errors.append(f"{path}: comparison winner must be a non-empty string")
    if not isinstance(comparison.get("reasoning"), str) or not comparison["reasoning"]:
        errors.append(f"{path}: comparison reasoning must be a non-empty string")
    for field in ("rubric", "output_quality", "expectation_results"):
        if not isinstance(comparison.get(field), dict):
            errors.append(f"{path}: comparison {field} must be an object")

    expectation_results = comparison.get("expectation_results")
    if isinstance(expectation_results, dict):
        for label, result in sorted(expectation_results.items()):
            if not isinstance(label, str):
                errors.append(f"{path}: comparison expectation_results keys must be strings")
                continue
            if not isinstance(result, dict):
                errors.append(f"{path}: expectation_results.{label} must be an object")
                continue
            for int_field in ("passed", "total"):
                if int_field in result and (
                    not isinstance(result.get(int_field), int) or isinstance(result.get(int_field), bool)
                ):
                    errors.append(f"{path}: expectation_results.{label}.{int_field} must be an integer")
            if "pass_rate" in result and (
                not isinstance(result.get("pass_rate"), (int, float)) or isinstance(result.get("pass_rate"), bool)
            ):
                errors.append(f"{path}: expectation_results.{label}.pass_rate must be a number")
            details = result.get("details")
            if details is not None:
                if not isinstance(details, list):
                    errors.append(f"{path}: expectation_results.{label}.details must be a list")
                else:
                    for idx, detail in enumerate(details):
                        if not isinstance(detail, dict):
                            errors.append(f"{path}: expectation_results.{label}.details[{idx}] must be an object")
                            continue
                        if not isinstance(detail.get("text"), str) or not detail["text"]:
                            errors.append(
                                f"{path}: expectation_results.{label}.details[{idx}].text "
                                "must be a non-empty string"
                            )
                        if not isinstance(detail.get("passed"), bool):
                            errors.append(f"{path}: expectation_results.{label}.details[{idx}].passed must be a boolean")
    return errors


def validate_analysis_output_schema(path: pathlib.Path) -> list[str]:
    analysis, errors = read_json(path)
    if errors:
        return errors
    if not analysis:
        return []

    errors = []
    comparison_summary = analysis.get("comparison_summary")
    if not isinstance(comparison_summary, dict):
        errors.append(f"{path}: analysis comparison_summary must be an object")
    else:
        for field in ("winner", "winner_skill", "loser_skill", "comparator_reasoning"):
            if not isinstance(comparison_summary.get(field), str):
                errors.append(f"{path}: comparison_summary.{field} must be a string")

    for field in ("winner_strengths", "loser_weaknesses"):
        values = analysis.get(field)
        if not isinstance(values, list):
            errors.append(f"{path}: analysis {field} must be a list")
        elif not all(isinstance(item, str) for item in values):
            errors.append(f"{path}: analysis {field} entries must be strings")

    instruction_following = analysis.get("instruction_following")
    if not isinstance(instruction_following, dict):
        errors.append(f"{path}: analysis instruction_following must be an object")

    suggestions = analysis.get("improvement_suggestions")
    if not isinstance(suggestions, list):
        errors.append(f"{path}: analysis improvement_suggestions must be a list")
    else:
        for idx, suggestion in enumerate(suggestions):
            if not isinstance(suggestion, dict):
                errors.append(f"{path}: improvement_suggestions[{idx}] must be an object")
                continue
            for field in ("priority", "category", "suggestion", "expected_impact"):
                if not isinstance(suggestion.get(field), str):
                    errors.append(f"{path}: improvement_suggestions[{idx}].{field} must be a string")

    transcript_insights = analysis.get("transcript_insights")
    if not isinstance(transcript_insights, dict):
        errors.append(f"{path}: analysis transcript_insights must be an object")
    return errors


def validate_trigger_eval_set_schema(path: pathlib.Path) -> list[str]:
    eval_set, errors = read_json_array(path)
    if errors:
        return errors
    if eval_set is None:
        return []

    errors = []
    if len(eval_set) != 20:
        errors.append(f"{path}: trigger eval set should contain exactly 20 queries")

    seen_trigger_values: set[bool] = set()
    for idx, item in enumerate(eval_set):
        if not isinstance(item, dict):
            errors.append(f"{path}: trigger eval set item {idx} must be an object")
            continue
        unknown_keys = sorted(set(item) - {"query", "should_trigger"})
        if unknown_keys:
            errors.append(f"{path}: trigger eval set item {idx} contains unknown key(s): {', '.join(unknown_keys)}")
        query = item.get("query")
        if not isinstance(query, str) or not query.strip():
            errors.append(f"{path}: trigger eval set item {idx}.query must be a non-empty string")
        should_trigger = item.get("should_trigger")
        if not isinstance(should_trigger, bool):
            errors.append(f"{path}: trigger eval set item {idx}.should_trigger must be a boolean")
        else:
            seen_trigger_values.add(should_trigger)

    if len(eval_set) == 20 and seen_trigger_values != {False, True}:
        errors.append(f"{path}: trigger eval set must mix should-trigger and should-not-trigger queries")
    return errors


def generated_output_schema_errors(repo_root: pathlib.Path) -> list[str]:
    errors = []
    workspaces = sorted(
        path
        for path in repo_root.rglob(f"*{EVAL_WORKSPACE_SUFFIX}")
        if path.is_dir() and ".git" not in path.parts
    )
    for workspace in workspaces:
        history_path = workspace / "history.json"
        if history_path.is_file():
            errors.extend(validate_history_output_schema(history_path))
        for path in sorted(workspace.rglob("eval_metadata.json")):
            errors.extend(validate_eval_metadata_output_schema(path))
        for path in sorted(workspace.rglob("grading.json")):
            errors.extend(validate_grading_output_schema(path))
        for path in sorted(workspace.rglob("metrics.json")):
            errors.extend(validate_metrics_output_schema(path))
        for path in sorted(workspace.rglob("timing.json")):
            errors.extend(validate_timing_output_schema(path))
        for path in sorted(workspace.rglob("feedback.json")):
            errors.extend(validate_feedback_output_schema(path))
        for path in sorted(workspace.rglob("comparison-*.json")):
            errors.extend(validate_comparison_output_schema(path))
        for path in sorted(workspace.rglob("analysis.json")):
            errors.extend(validate_analysis_output_schema(path))
        for pattern in ("eval_set*.json", "*trigger-eval*.json", "*trigger_eval*.json"):
            for path in sorted(workspace.rglob(pattern)):
                errors.extend(validate_trigger_eval_set_schema(path))
    benchmarks_dir = repo_root / "benchmarks"
    if benchmarks_dir.is_dir():
        for path in sorted(benchmarks_dir.rglob("benchmark.json")):
            errors.extend(validate_benchmark_output_schema(path))
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
            errors.extend(skill_package_safety_errors(skill_dir))
            errors.extend(packaged_artifact_errors(skill_dir))
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
    errors.extend(generated_output_schema_errors(repo_root))
    errors.extend(repository_eval_errors(repo_root))
    errors.extend(skill_link_errors(repo_root))
    if run_package_check:
        errors.extend(packaging_script_errors(repo_root))

    return errors


def validate_portable_package(skill_dir: pathlib.Path) -> list[str]:
    errors = []
    errors.extend(package_layout_errors(skill_dir))
    errors.extend(frontmatter_errors(skill_dir, "portable"))
    errors.extend(skill_package_safety_errors(skill_dir))
    errors.extend(packaged_artifact_errors(skill_dir))
    errors.extend(portable_body_policy_errors(skill_dir))
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
                max_cases=3,
                files_root=skill_dir,
                required_files_prefix="evals/files/",
            )
        )
        errors.extend(eval_fixture_usage_errors(skill_dir, skill_evals, str(evals_file)))
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
