#!/bin/sh
# MIMIC honeypot — daily reset script.
#
# Picks a random time inside a configurable window, sleeps until it, then
# wipes ephemeral state and restarts the honeypot so every day starts with a
# clean image.  The random offset prevents the restart from always hitting
# the same second, which would be a tell if an attacker were watching uptime.
#
# Deployment modes (set MIMIC_RESET_MODE):
#   docker   — restarts the "mimic" container via the Docker socket (default)
#   systemd  — restarts the mimic.service unit via systemctl
#
# Environment variables:
#   MIMIC_RESET_WINDOW  Max random delay in seconds (default: 10800 = 3 h)
#   MIMIC_RESET_MODE    "docker" (default) or "systemd"
#   MIMIC_DATA_DIR      Path to the data volume to wipe (default: /data)
#   MIMIC_CONTAINER     Container name for docker mode (default: mimic)
#   MIMIC_SERVICE       Service name for systemd mode (default: mimic.service)
#
# In Docker, this script runs as a sidecar that loops forever; the compose
# healthcheck keeps it visible.  Under systemd, a daily timer fires it once.

set -eu

WINDOW="${MIMIC_RESET_WINDOW:-10800}"
MODE="${MIMIC_RESET_MODE:-docker}"
DATA_DIR="${MIMIC_DATA_DIR:-/data}"
CONTAINER="${MIMIC_CONTAINER:-mimic}"
SERVICE="${MIMIC_SERVICE:-mimic.service}"

log() { printf '[mimic-reset] %s  %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

random_delay() {
    # POSIX-portable random: read 2 bytes from urandom, interpret as a number,
    # then mod by the window size.  Falls back to $RANDOM (bash/zsh/ash) if
    # /dev/urandom is unavailable.
    if [ -r /dev/urandom ]; then
        raw=$(od -An -tu4 -N4 /dev/urandom | tr -d ' ')
        echo $(( raw % WINDOW ))
    elif [ -n "${RANDOM:-}" ]; then
        echo $(( RANDOM % WINDOW ))
    else
        # Last resort: deterministic but still better than fixed midnight.
        echo $(( $(date +%s) % WINDOW ))
    fi
}

wipe_ephemeral() {
    # Remove quarantine contents (captured malware payloads) but keep the
    # directory itself and host_keys so the SSH fingerprint stays stable.
    if [ -d "${DATA_DIR}/quarantine" ]; then
        count=$(find "${DATA_DIR}/quarantine" -type f | wc -l)
        rm -rf "${DATA_DIR}/quarantine"/*
        log "wiped ${count} quarantine file(s)"
    fi
}

restart_honeypot() {
    case "${MODE}" in
        docker)
            log "restarting container '${CONTAINER}'"
            docker restart "${CONTAINER}"
            ;;
        systemd)
            log "restarting service '${SERVICE}'"
            systemctl restart "${SERVICE}"
            ;;
        *)
            log "ERROR: unknown MIMIC_RESET_MODE '${MODE}'"
            exit 1
            ;;
    esac
}

run_once() {
    delay=$(random_delay)
    log "next reset in ${delay}s (window=${WINDOW}s)"
    sleep "${delay}"

    log "starting daily reset"
    wipe_ephemeral
    restart_honeypot
    log "daily reset complete"
}

# ── Entry point ──────────────────────────────────────────────────────
# In Docker sidecar mode, loop forever (one reset per ~24 h cycle).
# Under systemd the timer fires us once, so we just run_once and exit.
if [ "${MODE}" = "docker" ]; then
    log "running in docker sidecar loop mode (window=${WINDOW}s)"
    while true; do
        run_once
        # After the reset, sleep roughly 24 hours before the next cycle.
        # The random delay inside run_once adds jitter to the exact time.
        sleep 86400
    done
else
    run_once
fi
