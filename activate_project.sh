#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# Security hardening
# ==============================================================================
umask 077
trap 'echo "⚠️ Script aborted." >&2; exit 1' ERR INT TERM

# ==============================================================================
# Color definitions
# ==============================================================================
BOLD=$(tput bold); GREEN=$(tput setaf 2); CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3); RED=$(tput setaf 1); RESET=$(tput sgr0)

# ==============================================================================
# Paths & logging
# ==============================================================================
readonly PROJECT_DIR="$HOME/projects/linkshield_project"
readonly VENV_DIR="$PROJECT_DIR/venv"
readonly LOG_DIR="$PROJECT_DIR/logs"
mkdir -p "$LOG_DIR"
readonly LOG_FILE="$LOG_DIR/run_$(date +'%F_%T').log"
exec > >(tee -a "$LOG_FILE") 2>&1

# ==============================================================================
# Helpers
# ==============================================================================
header() {
  clear
  echo "${BOLD}${GREEN}✅ Environment activated!${RESET}"
  echo "Project: ${BOLD}linkshield_project${RESET}"
  echo "User: $(whoami)@$(hostname)"
  if git -C "$PROJECT_DIR" rev-parse --is-inside-work-tree &>/dev/null; then
    echo "Git: branch $(git -C "$PROJECT_DIR" rev-parse --abbrev-ref HEAD) | last commit $(git -C "$PROJECT_DIR" log -1 --pretty=format:'%h %ad by %an' --date=short)"
  fi
  echo "Log file: $LOG_FILE"
  echo
}

check_command() {
  command -v "$1" &>/dev/null || { echo "${YELLOW}⚠️ Warning:${RESET} '$1' not found."; return 1; }
  return 0
}

pause() { read -rp "Press Enter to continue…"; }

# ==============================================================================
# Actions
# ==============================================================================
run_tests() {
  echo "${CYAN}▶️ Running tests…${RESET}"
  DEBUG_TIMING=1 python3 -m unittest scanner/test_link_scanner.py
  pause
}

open_httpbin() {
  echo "${CYAN}🌐 Opening httpbin…${RESET}"
  if check_command chromium-browser; then
    chromium-browser https://httpbin.org/get &
  elif check_command xdg-open; then
    xdg-open https://httpbin.org/get
  else
    echo "${RED}❌ Browser not found!${RESET}"
  fi
  pause
}

open_vscode() {
  echo "${CYAN}🧠 Opening VS Code…${RESET}"
  if check_command code; then code "$PROJECT_DIR"; else echo "${RED}❌ 'code' not found!${RESET}"; fi
  pause
}

start_docker() {
  echo "${CYAN}🐳 Starting Docker…${RESET}"
  if command -v sudo &>/dev/null; then
    sudo -n service docker start || echo "${YELLOW}⚠️ Cannot start without password.${RESET}"
  else
    echo "${YELLOW}⚠️ 'sudo' not available.${RESET}"
  fi
  pause
}

show_dashboard() {
  echo "${CYAN}📊 Opening dashboard…${RESET}"
  local file="$PROJECT_DIR/dashboard/test_report.html"
  if [ -f "$file" ]; then
    if check_command xdg-open; then xdg-open "$file"
    elif check_command chromium-browser; then chromium-browser "$file" &
    fi
  else
    echo "${RED}❌ Dashboard not found!${RESET}"
  fi
  pause
}

new_feature() {
  echo "${CYAN}✨ New feature…${RESET}"
  # כאן הקוד שלך
  pause
}

# ==============================================================================
# Menu
# ==============================================================================
main_menu() {
  # קודם מגדירים את רשימת האפשרויות
  options=(
    "Run link scanner tests"
    "Open httpbin.org in Chromium"
    "Open project in VS Code"
    "Start Docker daemon (WSL)"
    "Show test dashboard (HTML)"
    "New feature (placeholder)"
    "Exit"
  )
  # עכשיו אפשר להשתמש ב־options בלי שגיאה
  PS3="${BOLD}Choose option [1-${#options[@]}]: ${RESET}"
  select opt in "${options[@]}"; do
    case $REPLY in
      1) run_tests ;;
      2) open_httpbin ;;
      3) open_vscode ;;
      4) start_docker ;;
      5) show_dashboard ;;
      6) new_feature ;;
      7) echo "${GREEN}👋 Goodbye!${RESET}"; exit 0 ;;
      *) echo "${YELLOW}❌ Invalid option. Choose 1-${#options[@]}.${RESET}";;
    esac
    # בלי break – חוזר אוטומטית למסך התפריט
  done
}

# ==============================================================================
# Start
# ==============================================================================
cd "$PROJECT_DIR" || { echo "${RED}❌ Cannot cd to $PROJECT_DIR${RESET}"; exit 1; }
if [ -f "$VENV_DIR/bin/activate" ]; then
  source "$VENV_DIR/bin/activate"
  export PYTHONPATH="$PROJECT_DIR"
else
  echo "${YELLOW}⚠️ venv not found${RESET}"
fi

