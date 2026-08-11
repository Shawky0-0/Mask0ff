#!/usr/bin/env bash
# Validate and deploy the development copy to OpenCode's global discovery paths.
# Usage: ./sync-skill.sh [--verify-only]
set -eu

DEV="$(cd "$(dirname "$0")" && pwd)"
CONFIG_ROOT="$HOME/.config/opencode"
INSTALLED_SKILL="$CONFIG_ROOT/skills/mask0ff"
INSTALLED_AGENT="$CONFIG_ROOT/agents/mask0ff.md"
INSTALLED_CONFIG="$CONFIG_ROOT/opencode.json"
SOURCE_AGENT="$DEV/assets/opencode/agents/mask0ff.md"
SOURCE_CONFIG="$DEV/assets/opencode/opencode.json"
BACKUP_ROOT="$HOME/.config/opencode-backups"

require_source() {
  test -f "$DEV/SKILL.md"
  test -f "$SOURCE_AGENT"
  test -f "$SOURCE_CONFIG"
}

validate_skill() {
  skill="$1"
  (
    cd "$skill"
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/mask0ff.py integrity --root .
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/mask0ff.py audit --root . --fail-on-issues
    PYTHONDONTWRITEBYTECODE=1 python3 evals/run_evals.py --require-dataset
  )
}

validate_layout() {
  skill="$1"
  agent="$2"
  config="$3"
  verify_root="$(mktemp -d "${TMPDIR:-/tmp}/mask0ff-opencode-verify.XXXXXX")"
  mkdir -p "$verify_root/.opencode/skills" "$verify_root/.opencode/agents"
  ln -s "$skill" "$verify_root/.opencode/skills/mask0ff"
  ln -s "$agent" "$verify_root/.opencode/agents/mask0ff.md"
  ln -s "$config" "$verify_root/opencode.json"
  status=0
  (
    cd "$skill"
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/mask0ff.py opencode "$verify_root"
  ) || status=$?
  rm -f -- "$verify_root/.opencode/skills/mask0ff" "$verify_root/.opencode/agents/mask0ff.md" "$verify_root/opencode.json"
  rmdir -- "$verify_root/.opencode/skills" "$verify_root/.opencode/agents" "$verify_root/.opencode" "$verify_root"
  return "$status"
}

require_source

if [ "${1:-}" = "--verify-only" ]; then
  validate_skill "$INSTALLED_SKILL"
  validate_layout "$INSTALLED_SKILL" "$INSTALLED_AGENT" "$INSTALLED_CONFIG"
  exit 0
fi
if [ "$#" -ne 0 ]; then
  echo "usage: $0 [--verify-only]" >&2
  exit 2
fi

echo "== Validate the development copy =="
validate_skill "$DEV"

mkdir -p "$CONFIG_ROOT/skills" "$CONFIG_ROOT/agents" "$BACKUP_ROOT"
STAGE_ROOT="$(mktemp -d "$CONFIG_ROOT/.mask0ff-stage.XXXXXX")"
STAGE_SKILL="$STAGE_ROOT/.opencode/skills/mask0ff"
STAGE_AGENT="$STAGE_ROOT/.opencode/agents/mask0ff.md"
STAGE_CONFIG="$STAGE_ROOT/opencode.json"
BACKUP=""
HAD_SKILL=0
HAD_AGENT=0
HAD_CONFIG=0
MUTATION_STARTED=0
COMMITTED=0

cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && [ "$MUTATION_STARTED" -eq 1 ] && [ "$COMMITTED" -eq 0 ]; then
    set +e
    [ ! -e "$INSTALLED_SKILL" ] || mv -- "$INSTALLED_SKILL" "$BACKUP/failed-new/skill"
    [ ! -e "$INSTALLED_AGENT" ] || mv -- "$INSTALLED_AGENT" "$BACKUP/failed-new/mask0ff.md"
    [ ! -e "$INSTALLED_CONFIG" ] || cp -a -- "$INSTALLED_CONFIG" "$BACKUP/failed-new/opencode.json"
    [ "$HAD_SKILL" -ne 1 ] || mv -- "$BACKUP/skill" "$INSTALLED_SKILL"
    [ "$HAD_AGENT" -ne 1 ] || mv -- "$BACKUP/mask0ff.md" "$INSTALLED_AGENT"
    if [ "$HAD_CONFIG" -eq 1 ]; then
      cp -a -- "$BACKUP/opencode.json" "$INSTALLED_CONFIG"
    else
      rm -f -- "$INSTALLED_CONFIG"
    fi
    echo "deployment failed; restored the previous OpenCode installation" >&2
  fi
  if [ -d "$STAGE_ROOT" ]; then
    case "$STAGE_ROOT" in
      "$CONFIG_ROOT/.mask0ff-stage."*) rm -rf -- "$STAGE_ROOT" ;;
      *) echo "refusing to remove unexpected stage path: $STAGE_ROOT" >&2 ;;
    esac
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$STAGE_SKILL" "$(dirname "$STAGE_AGENT")"
cp -a "$DEV/." "$STAGE_SKILL/"
rm -rf -- "$STAGE_SKILL/.git" "$STAGE_SKILL/__pycache__" "$STAGE_SKILL/.pytest_cache"
find "$STAGE_SKILL" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$STAGE_SKILL" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
install -m 0644 "$SOURCE_AGENT" "$STAGE_AGENT"

# Preserve unrelated global OpenCode settings while adding the adapter's skill permissions.
python3 - "$INSTALLED_CONFIG" "$SOURCE_CONFIG" "$STAGE_CONFIG" <<'PY'
import json
import sys
from pathlib import Path

current_path, adapter_path, output_path = map(Path, sys.argv[1:])
current = json.loads(current_path.read_text(encoding="utf-8-sig")) if current_path.is_file() else {}
adapter = json.loads(adapter_path.read_text(encoding="utf-8-sig"))
if not isinstance(current, dict) or not isinstance(adapter, dict):
    raise SystemExit("OpenCode configuration must be a JSON object")
permissions = current.setdefault("permission", {})
if permissions == "allow":
    output_path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0)
if not isinstance(permissions, dict):
    raise SystemExit("existing OpenCode permission setting is not an object; merge it manually")
skill_permissions = permissions.setdefault("skill", {})
if not isinstance(skill_permissions, dict):
    raise SystemExit("existing OpenCode skill permission setting is not an object; merge it manually")
for key, value in adapter.get("permission", {}).get("skill", {}).items():
    skill_permissions[key] = value
current.setdefault("$schema", adapter.get("$schema"))
output_path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
PY

echo "== Validate the staged OpenCode layout =="
validate_skill "$STAGE_SKILL"
validate_layout "$STAGE_SKILL" "$STAGE_AGENT" "$STAGE_CONFIG"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="$(mktemp -d "$BACKUP_ROOT/mask0ff-$STAMP.XXXXXX")"
mkdir -p "$BACKUP/failed-new"

echo "== Back up and install =="
MUTATION_STARTED=1
if [ -e "$INSTALLED_SKILL" ]; then HAD_SKILL=1; mv -- "$INSTALLED_SKILL" "$BACKUP/skill"; fi
if [ -e "$INSTALLED_AGENT" ]; then HAD_AGENT=1; mv -- "$INSTALLED_AGENT" "$BACKUP/mask0ff.md"; fi
if [ -e "$INSTALLED_CONFIG" ]; then HAD_CONFIG=1; cp -a -- "$INSTALLED_CONFIG" "$BACKUP/opencode.json"; fi
mv -- "$STAGE_SKILL" "$INSTALLED_SKILL"
mv -- "$STAGE_AGENT" "$INSTALLED_AGENT"
install -m 0644 "$STAGE_CONFIG" "$INSTALLED_CONFIG"

echo "== Verify the fresh installation =="
validate_skill "$INSTALLED_SKILL"
validate_layout "$INSTALLED_SKILL" "$INSTALLED_AGENT" "$INSTALLED_CONFIG"
COMMITTED=1
rmdir -- "$BACKUP/failed-new"
echo "installed: $INSTALLED_SKILL"
echo "backup: $BACKUP"
