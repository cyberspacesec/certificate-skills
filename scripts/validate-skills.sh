#!/usr/bin/env bash
set -euo pipefail

roots=(".claude/skills" "skills")
failures=0
legacy_refs_file=$(mktemp "${TMPDIR:-/tmp}/certificate-skills-legacy-refs.XXXXXX")
trap 'rm -f "$legacy_refs_file"' EXIT

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  failures=$((failures + 1))
}

validate_evals_manifest() {
  local manifest="evals/skills-structure.json"
  local evals_file="evals/evals.json"

  if [[ ! -f "$manifest" ]]; then
    fail "missing skills eval manifest: $manifest"
    return
  fi

  if [[ ! -f "$evals_file" ]]; then
    fail "missing skill eval cases: $evals_file"
    return
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to validate eval manifests"
    return
  fi

  if ! python3 - "$manifest" "$evals_file" <<'PY'
import json
import pathlib
import sys

manifest_path = sys.argv[1]
evals_path = sys.argv[2]
with open(manifest_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
with open(evals_path, "r", encoding="utf-8") as fh:
    evals_data = json.load(fh)

errors = []
skill_names = {
    path.name
    for path in pathlib.Path("skills").iterdir()
    if path.is_dir() and (path / "SKILL.md").is_file()
}

def validate_skill_creator_evals(
    evals,
    label,
    expected_skill_name,
    min_cases=1,
    files_root=None,
    known_skill_names=None,
    require_expected_skill_ref=True,
):
    if evals.get("skill_name") != expected_skill_name:
        errors.append(f"{label} skill_name must be {expected_skill_name}")
    eval_cases = evals.get("evals")
    if not isinstance(eval_cases, list) or len(eval_cases) < min_cases:
        errors.append(f"{label} evals must contain at least {min_cases} case(s)")
        return

    seen = set()
    for idx, case in enumerate(eval_cases):
        case_id = case.get("id")
        if not isinstance(case_id, int):
            errors.append(f"{label} evals[{idx}].id must be an integer")
        elif case_id in seen:
            errors.append(f"{label} duplicate eval case id: {case_id}")
        else:
            seen.add(case_id)
        if not case.get("prompt"):
            errors.append(f"{label} evals[{idx}].prompt is required")
        if not case.get("expected_output"):
            errors.append(f"{label} evals[{idx}].expected_output is required")
        files = case.get("files")
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
            expected_output = str(case.get("expected_output", ""))
            if require_expected_skill_ref and expected_skill_name not in expected_text and expected_skill_name not in expected_output:
                errors.append(f"{label} evals[{idx}] should reference {expected_skill_name}")
            if known_skill_names and not any(skill_name in expected_text or skill_name in expected_output for skill_name in known_skill_names):
                errors.append(f"{label} evals[{idx}] should reference at least one known skill")

if data.get("suite") != "certificate-skills-structure":
    errors.append("suite must be certificate-skills-structure")
if not isinstance(data.get("version"), int):
    errors.append("version must be an integer")
cases = data.get("cases")
if not isinstance(cases, list) or not cases:
    errors.append("cases must be a non-empty list")
else:
    seen = set()
    for idx, case in enumerate(cases):
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

validate_skill_creator_evals(
    evals_data,
    "evals/evals.json",
    "certificate-skills",
    min_cases=1,
    files_root=pathlib.Path("."),
    known_skill_names=skill_names,
    require_expected_skill_ref=False,
)

for skill_name in sorted(skill_names):
    skill_evals_path = pathlib.Path("skills") / skill_name / "evals" / "evals.json"
    if not skill_evals_path.is_file():
        errors.append(f"{skill_evals_path}: missing per-skill eval manifest")
        continue
    with open(skill_evals_path, "r", encoding="utf-8") as fh:
        skill_evals = json.load(fh)
    validate_skill_creator_evals(
        skill_evals,
        str(skill_evals_path),
        skill_name,
        min_cases=2,
        files_root=pathlib.Path("skills") / skill_name,
    )

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY
  then
    failures=$((failures + 1))
  fi
}

validate_skill_links() {
  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to validate skill links"
    return
  fi

  if ! python3 - <<'PY'
import pathlib
import re
import sys
from urllib.parse import unquote

roots = [pathlib.Path(".claude/skills"), pathlib.Path("skills")]
link_re = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
errors = []

for root in roots:
    if not root.is_dir():
        continue
    for skill_file in sorted(root.glob("*/SKILL.md")):
        text = skill_file.read_text(encoding="utf-8")
        linked_targets = set()
        for match in link_re.finditer(text):
            raw_target = match.group(1).strip()
            target = raw_target.split("#", 1)[0]
            if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("/"):
                continue
            linked_targets.add(unquote(target))
            resolved = (skill_file.parent / unquote(target)).resolve()
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
            for reference_file in sorted(references_dir.iterdir()):
                if reference_file.is_file():
                    target = f"references/{reference_file.name}"
                    if target not in linked_targets:
                        errors.append(f"{skill_file}: reference file is not linked from SKILL.md: {target}")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY
  then
    failures=$((failures + 1))
  fi
}

validate_packaging_script() {
  local script="scripts/package-skills.py"

  if [[ ! -f "$script" ]]; then
    fail "missing skill packaging script: $script"
    return
  fi

  if [[ ! -x "$script" ]]; then
    fail "$script should be executable"
  fi

  if ! python3 "$script" --check >/tmp/certificate-skills-package-check.$$ 2>&1; then
    fail "$script --check failed:"
    cat /tmp/certificate-skills-package-check.$$ >&2
  fi
  rm -f /tmp/certificate-skills-package-check.$$
}

validate_tool_metadata_parity() {
  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to validate skill tool metadata parity"
    return
  fi

  if ! python3 - <<'PY'
import pathlib
import re
import sys

errors = []
portable_root = pathlib.Path("skills")
claude_root = pathlib.Path(".claude/skills")


def frontmatter_lines(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        return []
    try:
        close_index = lines[1:].index("---") + 1
    except ValueError:
        return []
    return lines[1:close_index]


def portable_tools(path):
    tools = set()
    in_tools = False
    for line in frontmatter_lines(path):
        if line.startswith("tools:"):
            in_tools = True
            tools.update(re.findall(r"\bcert_[A-Za-z0-9_]+\b", line))
            continue
        if in_tools:
            if re.match(r"^[A-Za-z0-9_-]+:", line):
                in_tools = False
                continue
            tools.update(re.findall(r"\bcert_[A-Za-z0-9_]+\b", line))
    return tools


def claude_tools(path):
    text = "\n".join(frontmatter_lines(path))
    return set(re.findall(r"mcp__certificate-skills__(cert_[A-Za-z0-9_]+)", text))


for skill_dir in sorted(path for path in portable_root.iterdir() if path.is_dir()):
    claude_file = claude_root / skill_dir.name / "SKILL.md"
    portable_file = skill_dir / "SKILL.md"
    if not claude_file.is_file() or not portable_file.is_file():
        continue
    portable = portable_tools(portable_file)
    claude = claude_tools(claude_file)
    if portable != claude:
        errors.append(
            f"{skill_dir.name}: portable tools {sorted(portable)} "
            f"do not match Claude Code allowed-tools {sorted(claude)}"
        )

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY
  then
    failures=$((failures + 1))
  fi
}

check_frontmatter() {
  local file=$1
  local dir_name=$2
  local root=${3:-}
  local name description tools allowed_tools close_line line_count frontmatter
  local xml_tag_re='<[[:alpha:]/][^>]*>'

  if [[ ! -f "$file" ]]; then
    fail "missing SKILL.md: $file"
    return
  fi

  line_count=$(awk 'END { print NR }' "$file")
  if [[ "$line_count" -gt 500 ]]; then
    fail "$file: SKILL.md should stay lightweight (found $line_count lines, expected <= 500)"
  fi

  if [[ ! "$dir_name" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
    fail "$file: skill directory should be lowercase hyphenated"
  fi

  if [[ "$(sed -n '1p' "$file")" != "---" ]]; then
    fail "$file: missing opening YAML frontmatter delimiter"
    return
  fi

  close_line=$(awk 'NR > 1 && $0 == "---" { print NR; exit }' "$file")
  if [[ -z "$close_line" ]]; then
    fail "$file: missing closing YAML frontmatter delimiter"
    return
  fi

  name=$(awk 'NR > 1 && $0 == "---" { exit } /^name:[[:space:]]*/ { sub(/^name:[[:space:]]*/, ""); print; exit }' "$file")
  description=$(awk 'NR > 1 && $0 == "---" { exit } /^description:[[:space:]]*/ { sub(/^description:[[:space:]]*/, ""); print; exit }' "$file")
  tools=$(awk 'NR > 1 && $0 == "---" { exit } /^tools:[[:space:]]*/ { print; exit }' "$file")
  allowed_tools=$(awk 'NR > 1 && $0 == "---" { exit } /^allowed-tools:[[:space:]]*/ { print; exit }' "$file")
  frontmatter=$(awk 'NR > 1 && $0 == "---" { exit } NR > 1 { print }' "$file")

  if [[ -z "$name" ]]; then
    fail "$file: missing frontmatter name"
  fi
  if [[ -n "$name" && "$name" != "$dir_name" ]]; then
    fail "$file: frontmatter name '$name' does not match directory '$dir_name'"
  fi
  if [[ -n "$name" && "${#name}" -gt 64 ]]; then
    fail "$file: frontmatter name is too long (${#name} characters, expected <= 64)"
  fi
  if [[ -n "$name" && ! "$name" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
    fail "$file: frontmatter name should use lowercase letters, numbers, and hyphens"
  fi
  if [[ -n "$name" && "$name" =~ $xml_tag_re ]]; then
    fail "$file: frontmatter name must not contain XML tags"
  fi
  if [[ -n "$name" && ( "$name" == *anthropic* || "$name" == *claude* ) ]]; then
    fail "$file: frontmatter name must not contain reserved words: anthropic, claude"
  fi

  if [[ -z "$description" ]]; then
    fail "$file: missing frontmatter description"
  fi
  if [[ -n "$description" && "${#description}" -gt 1024 ]]; then
    fail "$file: frontmatter description is too long (${#description} characters, expected <= 1024)"
  fi
  if [[ -n "$description" && "$description" =~ $xml_tag_re ]]; then
    fail "$file: frontmatter description must not contain XML tags"
  fi
  if [[ -n "$description" && ( "$description" != *"Use when"* || "$description" != *"Triggers on mentions"* ) ]]; then
    fail "$file: frontmatter description should explain when the skill triggers"
  fi

  if [[ "$root" == "skills" ]]; then
    if [[ -z "$tools" ]]; then
      fail "$file: portable skill frontmatter should declare tools"
    fi
    if [[ -n "$allowed_tools" ]]; then
      fail "$file: portable skill frontmatter should use tools, not allowed-tools"
    fi
  elif [[ "$root" == ".claude/skills" ]]; then
    if [[ -z "$allowed_tools" ]]; then
      fail "$file: Claude Code skill frontmatter should declare allowed-tools"
    elif [[ "$frontmatter" != *"mcp__certificate-skills__"* ]]; then
      fail "$file: allowed-tools should use the certificate-skills MCP server prefix"
    fi
    if [[ -n "$tools" ]]; then
      fail "$file: Claude Code skill frontmatter should use allowed-tools, not tools"
    fi
  fi
}

check_claude_prompt_sections() {
  local file=$1
  local heading
  local required_headings=(
    "## When to Use"
    "## When NOT to Use"
    "## Instructions"
    "## Anti-Patterns"
  )

  for heading in "${required_headings[@]}"; do
    if ! grep -qxF "$heading" "$file"; then
      fail "$file: missing executable prompt section: $heading"
    fi
  done
}

check_skill_package_layout() {
  local dir=$1
  local file base
  local allowed_resource_dirs=" references scripts assets evals "

  while IFS= read -r file; do
    base=$(basename "$file")
    if [[ -d "$file" ]]; then
      if [[ "$allowed_resource_dirs" != *" $base "* ]]; then
        fail "$dir: unsupported bundled resource directory '$base' (expected references, scripts, assets, or evals)"
      fi
    elif [[ -f "$file" && "$base" != "SKILL.md" ]]; then
      fail "$dir: unsupported top-level skill package file '$base' (expected SKILL.md or files under bundled resource directories)"
    fi
  done < <(find "$dir" -mindepth 1 -maxdepth 1 | sort)
}

get_description() {
  awk 'NR > 1 && $0 == "---" { exit } /^description:[[:space:]]*/ { sub(/^description:[[:space:]]*/, ""); print; exit }' "$1"
}

check_portable_skill_prompt() {
  local dir=$1
  local dir_name=$2
  local file="$dir/SKILL.md"
  local claude_file=".claude/skills/$dir_name/SKILL.md"
  local portable_description claude_description

  if grep -nE '^(## Installation|### (Download Binary|Build from Source|Install Globally|Verify Installation|Install as Go Module))$|see Installation section above' "$file" >/tmp/certificate-skills-installation-check.$$; then
    fail "$file: portable SKILL.md should not duplicate repository installation instructions:"
    cat /tmp/certificate-skills-installation-check.$$ >&2
  fi
  rm -f /tmp/certificate-skills-installation-check.$$

  if [[ -f "$claude_file" ]]; then
    portable_description=$(get_description "$file")
    claude_description=$(get_description "$claude_file")
    if [[ "$portable_description" != "$claude_description" ]]; then
      fail "$file: portable description should match Claude Code skill trigger description"
    fi
  fi
}

for root in "${roots[@]}"; do
  if [[ ! -d "$root" ]]; then
    fail "missing skills root: $root"
    continue
  fi

  while IFS= read -r dir; do
    check_frontmatter "$dir/SKILL.md" "$(basename "$dir")" "$root"
    check_skill_package_layout "$dir"
    if [[ "$root" == ".claude/skills" ]]; then
      check_claude_prompt_sections "$dir/SKILL.md"
    fi
    if [[ "$root" == "skills" ]]; then
      check_portable_skill_prompt "$dir" "$(basename "$dir")"
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 1 -type d | sort)
done

if [[ -d ".claude/skills" && -d "skills" ]]; then
  diff_output=$(comm -3 \
    <(find .claude/skills -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort) \
    <(find skills -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort))
  if [[ -n "$diff_output" ]]; then
    fail ".claude/skills and skills contain different skill directories:"
    printf '%s\n' "$diff_output" >&2
  fi
fi

if command -v rg >/dev/null 2>&1; then
  if rg -n 'certificate-hacker|cert-hacker' .claude/skills skills evals README.md CLAUDE.md docs >"$legacy_refs_file"; then
    fail "legacy certificate-hacker/cert-hacker references remain:"
    cat "$legacy_refs_file" >&2
  fi
else
  if grep -RInE 'certificate-hacker|cert-hacker' .claude/skills skills evals README.md CLAUDE.md docs >"$legacy_refs_file"; then
    fail "legacy certificate-hacker/cert-hacker references remain:"
    cat "$legacy_refs_file" >&2
  fi
fi

validate_evals_manifest
validate_skill_links
validate_packaging_script
validate_tool_metadata_parity

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

printf 'Skill structure validation passed.\n'
