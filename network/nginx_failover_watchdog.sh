#!/bin/bash
set -u

CHECK_INTERVAL="${NGINX_FAILOVER_INTERVAL:-5}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

PID_FILE=".watchdog.pid"
if [ -f "$PID_FILE" ]; then
    old_pid=$(cat "$PID_FILE")
    if ps -p "$old_pid" > /dev/null 2>&1; then
        echo "[NGINX-FAILOVER] Another watchdog is already running (PID: $old_pid). Exiting."
        exit 1
    fi
fi
echo $$ > "$PID_FILE"
trap 'rm -f "$PID_FILE"; exit 0' INT TERM EXIT

SHIELDS=(
    "nginx-shield-main:8080:nginx-shield-main-failover"
    "nginx-shield-annex:8090:nginx-shield-annex-failover"
    "nginx-shield-pubad:8100:nginx-shield-pubad-failover"
)

# Track failures per shield to prevent aggressive takeover
declare -A FAILURE_COUNTS
for shield in "${SHIELDS[@]}"; do
    IFS=":" read -r name port failover <<< "$shield"
    FAILURE_COUNTS["$name"]=0
done

log_watchdog() {
    echo "[NGINX-FAILOVER] $1"
}

is_container_running() {
    local name=$1
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = "true" ]
}

is_container_exists() {
    local name=$1
    docker inspect "$name" >/dev/null 2>&1
}

is_port_open() {
    local port=$1
    nc -z -w 1 127.0.0.1 "$port" >/dev/null 2>&1
}

start_redirector() {
    local port=$1
    local redirect_container=$2

    if is_container_exists "$redirect_container"; then
        if docker start "$redirect_container" >/dev/null 2>&1; then
            log_watchdog "Port $port is now serving the automatic redirect page (restarted container)."
            return 0
        fi
        # Fallback to recreate if start fails
        docker rm -f "$redirect_container" >/dev/null 2>&1 || true
    fi

    if docker run -d --name "$redirect_container" \
        -p "${port}:80" \
        -v "$SCRIPT_DIR/nginx-failover-redirect/default.conf:/etc/nginx/conf.d/default.conf:ro" \
        -v "$SCRIPT_DIR/nginx-failover-redirect/index.html:/usr/share/nginx/html/index.html:ro" \
        nginx:stable-alpine >/dev/null 2>&1; then
        log_watchdog "Port $port is now serving the automatic redirect page."
        return 0
    else
        return 1
    fi
}

stop_redirector() {
    local redirect_container=$1
    docker rm -f "$redirect_container" >/dev/null 2>&1 || true
}

manage_shield() {
    local shield_container=$1
    local port=$2
    local redirect_container=$3

    if is_container_running "$shield_container"; then
        FAILURE_COUNTS["$shield_container"]=0
        if is_container_running "$redirect_container"; then
            stop_redirector "$redirect_container"
            log_watchdog "$shield_container is back. Removed temporary redirector on port $port."
        fi
        return
    fi

    let FAILURE_COUNTS["$shield_container"]++
    local fails=${FAILURE_COUNTS["$shield_container"]}

    if [ "$fails" -lt 2 ]; then
        return
    fi

    if is_container_running "$redirect_container"; then
        return
    fi

    if is_port_open "$port"; then
        log_watchdog "Port $port is in use, so redirector for $shield_container cannot start yet."
        return
    fi

    start_redirector "$port" "$redirect_container" ||
        log_watchdog "Could not start redirector on port $port for $shield_container."
}

log_watchdog "Watching all Nginx shields. Any stopped shield port will redirect to an available shield."

while true; do
    for shield in "${SHIELDS[@]}"; do
        IFS=":" read -r shield_container port redirect_container <<< "$shield"
        manage_shield "$shield_container" "$port" "$redirect_container"
    done

    sleep "$CHECK_INTERVAL"
done
