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
import sys

manifest_path = sys.argv[1]
evals_path = sys.argv[2]
with open(manifest_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
with open(evals_path, "r", encoding="utf-8") as fh:
    evals_data = json.load(fh)

errors = []
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

if evals_data.get("suite") != "certificate-skills":
    errors.append("evals/evals.json suite must be certificate-skills")
if not isinstance(evals_data.get("version"), int):
    errors.append("evals/evals.json version must be an integer")
eval_cases = evals_data.get("cases")
if not isinstance(eval_cases, list) or not eval_cases:
    errors.append("evals/evals.json cases must be a non-empty list")
else:
    seen = set()
    for idx, case in enumerate(eval_cases):
        case_id = case.get("id")
        if not case_id:
            errors.append(f"evals/evals.json cases[{idx}].id is required")
        elif case_id in seen:
            errors.append(f"duplicate eval case id: {case_id}")
        else:
            seen.add(case_id)
        if not case.get("prompt"):
            errors.append(f"evals/evals.json cases[{idx}].prompt is required")
        assertions = case.get("assertions")
        if not isinstance(assertions, list) or not assertions:
            errors.append(f"evals/evals.json cases[{idx}].assertions must be a non-empty list")
        expected_skills = case.get("expected_skills")
        if not isinstance(expected_skills, list) or not expected_skills:
            errors.append(f"evals/evals.json cases[{idx}].expected_skills must be a non-empty list")

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
        for match in link_re.finditer(text):
            raw_target = match.group(1).strip()
            target = raw_target.split("#", 1)[0]
            if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("/"):
                continue
            resolved = (skill_file.parent / unquote(target)).resolve()
            skill_root = skill_file.parent.resolve()
            try:
                resolved.relative_to(skill_root)
            except ValueError:
                errors.append(f"{skill_file}: link escapes skill package: {raw_target}")
                continue
            if not resolved.exists():
                errors.append(f"{skill_file}: missing linked resource: {raw_target}")

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
  local name description close_line line_count

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

  if [[ -z "$name" ]]; then
    fail "$file: missing frontmatter name"
  elif [[ "$name" != "$dir_name" ]]; then
    fail "$file: frontmatter name '$name' does not match directory '$dir_name'"
  elif [[ ! "$name" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
    fail "$file: frontmatter name should be lowercase hyphenated"
  fi

  if [[ -z "$description" ]]; then
    fail "$file: missing frontmatter description"
  elif [[ "${#description}" -gt 1024 ]]; then
    fail "$file: frontmatter description is too long (${#description} characters, expected <= 1024)"
  elif [[ "$description" != *"Use when"* || "$description" != *"Triggers on mentions"* ]]; then
    fail "$file: frontmatter description should explain when the skill triggers"
  fi
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
    check_frontmatter "$dir/SKILL.md" "$(basename "$dir")"
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

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

printf 'Skill structure validation passed.\n'
