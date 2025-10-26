#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'


GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)
RESET=$(tput sgr0)


PROJECT_DIR="$HOME/projects/linkshield_project"
if [[ ! -d "$PROJECT_DIR/app" ]]; then
  echo "${RED}❌ Error: Not in project root.${RESET}"
  exit 1
fi


export PYTHONPATH="$PROJECT_DIR"
echo "${GREEN}✅ PYTHONPATH set to: $PYTHONPATH${RESET}"


if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  if [[ -f "$PROJECT_DIR/venv/bin/activate" ]]; then
    source "$PROJECT_DIR/venv/bin/activate"
    echo "${GREEN}✅ venv activated.${RESET}"
  else
    echo "${YELLOW}⚠️ Warning: venv not found.${RESET}"
  fi
else
  echo "${YELLOW}ℹ️ venv already active.${RESET}"
fi


read -rp "🧪 Run tests now? [y/N] " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
  pytest tests/
fi
