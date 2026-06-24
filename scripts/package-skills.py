#!/usr/bin/env python3
"""Package portable skills into .skill archives.

The .skill format is a zip archive of one skill package directory containing
SKILL.md and optional bundled resource directories such as references/ and evals/.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import zipfile


ALLOWED_RESOURCE_DIRS = {"references", "scripts", "assets", "evals"}
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
XML_TAG_RE = re.compile(r"<[A-Za-z/][^>]*>")
RESERVED_NAME_PARTS = ("anthropic", "claude")


def iter_skill_dirs(skills_root: pathlib.Path, requested: list[str]) -> list[pathlib.Path]:
    if requested:
        skill_dirs = [skills_root / name for name in requested]
    else:
        skill_dirs = sorted(path for path in skills_root.iterdir() if path.is_dir())

    missing = [path.name for path in skill_dirs if not (path / "SKILL.md").is_file()]
    if missing:
        raise SystemExit(f"missing SKILL.md for skill(s): {', '.join(sorted(missing))}")
    return skill_dirs


def validate_package_layout(skill_dir: pathlib.Path) -> None:
    for child in sorted(skill_dir.iterdir()):
        if child.name == "SKILL.md" and child.is_file():
            continue
        if child.is_dir() and child.name in ALLOWED_RESOURCE_DIRS:
            continue
        raise SystemExit(
            f"{skill_dir}: unsupported package entry {child.name!r}; "
            "expected SKILL.md or references/, scripts/, assets/, evals/"
        )


def unquote_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def read_frontmatter(skill_file: pathlib.Path) -> dict[str, str]:
    lines = skill_file.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise SystemExit(f"{skill_file}: missing opening YAML frontmatter delimiter")

    try:
        close_index = lines[1:].index("---") + 1
    except ValueError as exc:
        raise SystemExit(f"{skill_file}: missing closing YAML frontmatter delimiter") from exc

    fields = {}
    for line in lines[1:close_index]:
        if line.startswith("name:"):
            fields["name"] = unquote_scalar(line.split(":", 1)[1])
        elif line.startswith("description:"):
            fields["description"] = unquote_scalar(line.split(":", 1)[1])
    return fields


def validate_frontmatter(skill_dir: pathlib.Path) -> None:
    skill_file = skill_dir / "SKILL.md"
    fields = read_frontmatter(skill_file)
    name = fields.get("name", "")
    description = fields.get("description", "")
    errors = []

    if not name:
        errors.append("missing frontmatter name")
    else:
        if name != skill_dir.name:
            errors.append(f"frontmatter name {name!r} does not match directory {skill_dir.name!r}")
        if len(name) > 64:
            errors.append(f"frontmatter name is too long ({len(name)} characters, expected <= 64)")
        if not NAME_RE.fullmatch(name):
            errors.append("frontmatter name should use lowercase letters, numbers, and hyphens")
        if XML_TAG_RE.search(name):
            errors.append("frontmatter name must not contain XML tags")
        if any(part in name for part in RESERVED_NAME_PARTS):
            errors.append("frontmatter name must not contain reserved words: anthropic, claude")

    if not description:
        errors.append("missing frontmatter description")
    else:
        if len(description) > 1024:
            errors.append(
                f"frontmatter description is too long ({len(description)} characters, expected <= 1024)"
            )
        if XML_TAG_RE.search(description):
            errors.append("frontmatter description must not contain XML tags")
        if "Use when" not in description or "Triggers on mentions" not in description:
            errors.append("frontmatter description should explain when the skill triggers")

    if errors:
        details = "\n  - ".join(errors)
        raise SystemExit(f"{skill_file}: invalid skill metadata:\n  - {details}")


def archive_members(skill_dir: pathlib.Path) -> list[pathlib.Path]:
    members = []
    for path in sorted(skill_dir.rglob("*")):
        if path.is_file():
            members.append(path)
    return members


def package_skill(skill_dir: pathlib.Path, output_dir: pathlib.Path, check: bool) -> pathlib.Path:
    validate_package_layout(skill_dir)
    validate_frontmatter(skill_dir)
    output_path = output_dir / f"{skill_dir.name}.skill"

    if check:
        return output_path

    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in archive_members(skill_dir):
            archive.write(path, path.relative_to(skill_dir))
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Package portable skills into .skill archives.")
    parser.add_argument("skills", nargs="*", help="Optional skill directory names to package.")
    parser.add_argument("--skills-root", default="skills", help="Portable skills root directory.")
    parser.add_argument("--output-dir", default="dist/skills", help="Directory for .skill archives.")
    parser.add_argument("--check", action="store_true", help="Validate package inputs without writing archives.")
    args = parser.parse_args()

    skills_root = pathlib.Path(args.skills_root)
    output_dir = pathlib.Path(args.output_dir)
    if not skills_root.is_dir():
        raise SystemExit(f"missing skills root: {skills_root}")

    packaged = []
    for skill_dir in iter_skill_dirs(skills_root, args.skills):
        output_path = package_skill(skill_dir, output_dir, args.check)
        packaged.append(output_path)
        action = "checked" if args.check else "packaged"
        print(f"{action} {skill_dir} -> {output_path}")

    if not packaged:
        raise SystemExit("no skills found to package")
    return 0


if __name__ == "__main__":
    sys.exit(main())
