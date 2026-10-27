#!/usr/bin/env bash
# Linux Bash Synchronization Service Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PYTHON_BIN="$(which python3 || which python)"
SYNC_TOOL="$PROJECT_DIR/sync_tool.py"
LOG_FILE="$PROJECT_DIR/sync.log"

MODE="${1:-batch}"
DRY_RUN="${2:-}"

run_single() {
    local ts
    ts=$(date -Iseconds)
    echo "[$ts] Starting synchronization run..." >> "$LOG_FILE"
    
    local args=("$PYTHON_BIN" "$SYNC_TOOL" "sync")
    if [ "$DRY_RUN" = "--dry-run" ]; then
        args+=("--dry-run")
    fi

    "${args[@]}" >> "$LOG_FILE" 2>&1 || true
    local exit_code=$?
    
    local end_ts
    end_ts=$(date -Iseconds)
    echo "[$end_ts] Synchronization finished with exit code $exit_code" >> "$LOG_FILE"
    return $exit_code
}

if [ "$MODE" = "batch" ]; then
    run_single
elif [ "$MODE" = "daemon" ]; then
    INTERVAL=900
    echo "[+] Linux daemon mode started. Interval: $INTERVAL seconds. Press Ctrl+C to stop."
    while true; do
        run_single
        sleep "$INTERVAL"
    done
else
    echo "Usage: $0 [batch|daemon] [--dry-run]"
    exit 1
fi
