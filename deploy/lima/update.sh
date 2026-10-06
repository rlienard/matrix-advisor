#!/usr/bin/env bash
# Continuous deployment of the demo inside the Lima VM (pull-based, nothing to configure on GitHub).
#
# Run every 2 minutes by a systemd user timer (installed by lima-demo.sh, or `update.sh --install`):
# when origin/main has a new commit whose GitHub checks all passed, fast-forward the checkout,
# rebuild the stack and wait for /healthz. A commit whose CI or deployment failed is skipped until
# the next commit. The VM only makes outbound requests (git fetch + the public GitHub API).
#
#   update.sh              deploy origin/main if it is new and green (what the timer runs)
#   update.sh --force      deploy origin/main now, without waiting for CI
#   update.sh --reset      same as --force, and delete the volumes first (proposals, audit, admin password)
#   update.sh --install    install and start the systemd timer
#
# Logs: journalctl --user -u matrix-advisor-update -f
set -euo pipefail

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
STATE_DIR=${XDG_STATE_HOME:-$HOME/.local/state}/matrix-advisor
UNIT=matrix-advisor-update
HEALTH_URL=${HEALTH_URL:-http://127.0.0.1:8080/healthz}
COMPOSE=(docker compose -f docker-compose.yml -f deploy/lima/docker-compose.lima.yml --profile demo)
export MA_CONFIG_TEMPLATE=/app/deploy/config.lima.yaml

log() { echo "[$(date -u +%FT%TZ)] $*"; }

# GitHub "owner/repo" from the origin URL (https or ssh form).
github_repo() {
  git remote get-url origin | sed -E 's#^(https://|git@)github\.com[:/]##; s#\.git$##'
}

# Aggregated state of the GitHub check runs of a commit: success, pending, failure or none.
ci_state() {
  curl -fsS --max-time 20 -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$(github_repo)/commits/$1/check-runs?per_page=100" |
  python3 -c '
import json, sys
runs = json.load(sys.stdin)["check_runs"]
if not runs:
    print("none")
elif any(r["status"] != "completed" for r in runs):
    print("pending")
elif all(r["conclusion"] in ("success", "neutral", "skipped") for r in runs):
    print("success")
else:
    print("failure")
'
}

wait_healthy() {
  for _ in $(seq 60); do
    curl -fsS --max-time 3 "$HEALTH_URL" >/dev/null 2>&1 && return 0
    sleep 3
  done
  return 1
}

# Called from an `if`, where set -e is off: every step checks its own status.
deploy() {
  local target=$1 reset=$2
  log "deploying $(git log -1 --format='%h %s' "$target")"
  git merge -q --ff-only "$target" || { log "FAILED: cannot fast-forward the checkout"; return 1; }
  if [ "$reset" = 1 ]; then
    log "deleting volumes (--reset)"
    "${COMPOSE[@]}" down -v || return 1
  fi
  "${COMPOSE[@]}" up -d --build --remove-orphans || { log "FAILED: docker compose up"; return 1; }
  if ! wait_healthy; then
    "${COMPOSE[@]}" logs --tail 50 matrix-advisor || true
    log "FAILED: $HEALTH_URL did not answer after the rebuild"
    return 1
  fi
  docker image prune -f >/dev/null || true
  log "deployed $(git rev-parse --short HEAD), healthy"
}

install_timer() {
  local dir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user env=""
  mkdir -p "$dir"
  # Lima's docker template runs rootless Docker: point the service at the user's daemon.
  [ -S "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/docker.sock" ] && env="Environment=DOCKER_HOST=unix://%t/docker.sock"
  cat >"$dir/$UNIT.service" <<EOF
[Unit]
Description=Matrix Advisor: deploy origin/main when CI is green
After=docker.service network-online.target

[Service]
Type=oneshot
$env
ExecStart=$REPO_DIR/deploy/lima/update.sh
TimeoutStartSec=30min
EOF
  cat >"$dir/$UNIT.timer" <<EOF
[Unit]
Description=Matrix Advisor: check origin/main every 2 minutes

[Timer]
OnBootSec=1min
OnUnitInactiveSec=2min

[Install]
WantedBy=timers.target
EOF
  # User services must keep running without an open session (limactl shell exits).
  loginctl show-user "$USER" -p Linger 2>/dev/null | grep -q yes || sudo loginctl enable-linger "$USER"
  systemctl --user daemon-reload
  systemctl --user enable --now "$UNIT.timer"
  log "timer installed; logs: journalctl --user -u $UNIT -f"
}

main() {
  local mode=${1:-auto}
  cd "$REPO_DIR"
  case "$mode" in
    --install) install_timer; return ;;
    auto|--force|--reset) ;;
    *) echo "usage: $0 [--force|--reset|--install]" >&2; return 2 ;;
  esac

  mkdir -p "$STATE_DIR"
  exec 9>"$STATE_DIR/lock"
  if [ "$mode" = auto ]; then
    flock -n 9 || { log "another update is running"; return 0; }
  else
    flock 9
  fi

  git fetch -q origin main
  local target deployed skipped state
  target=$(git rev-parse origin/main)

  if [ "$mode" = auto ]; then
    deployed=$(cat "$STATE_DIR/deployed" 2>/dev/null || true)
    skipped=$(cat "$STATE_DIR/skipped" 2>/dev/null || true)
    if [ "$target" = "$deployed" ] || [ "$target" = "$skipped" ]; then
      return 0
    fi
    state=$(ci_state "$target") || { log "GitHub API unreachable, retrying later"; return 0; }
    case "$state" in
      success) ;;
      pending|none) log "waiting for CI on ${target:0:7}"; return 0 ;;
      *) log "CI failed on ${target:0:7}, not deploying"; echo "$target" >"$STATE_DIR/skipped"; return 0 ;;
    esac
  fi

  if deploy "$target" "$([ "$mode" = --reset ] && echo 1 || echo 0)"; then
    echo "$target" >"$STATE_DIR/deployed"
  else
    echo "$target" >"$STATE_DIR/skipped"
    return 1
  fi
}

# The checkout replaces this file while it runs: bash has read the whole of main() before calling it.
main "$@"; exit
