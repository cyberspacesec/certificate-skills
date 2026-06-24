#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  printf 'ERROR: python3 is required to validate skill structure\n' >&2
  exit 1
fi

python3 "$(dirname "$0")/skill_validation.py" "$@"
