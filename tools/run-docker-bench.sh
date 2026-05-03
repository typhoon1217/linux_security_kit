#!/usr/bin/env bash
# Run Docker Bench for Security against every running LXC that has docker.
# Docker Bench is the official CIS Docker Benchmark check script.
# Runs in a privileged docker container that inspects the host docker daemon.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib/common.sh"

require_root

OUT_DIR=${OUT_DIR:-/root/security-audit-results/docker-bench}
mkdir -p "$OUT_DIR"

run_bench() {
  local ct="$1"
  local out="$OUT_DIR/ct${ct}.log"
  pct exec "$ct" -- bash -c '
    docker pull docker/docker-bench-security:latest >/dev/null 2>&1 || true
    docker run --rm --net host --pid host \
      -v /etc:/etc:ro \
      -v /var/lib:/var/lib:ro \
      -v /var/run/docker.sock:/var/run/docker.sock:ro \
      docker/docker-bench-security 2>&1
  ' > "$out" 2>&1 || true

  local fail=$(grep -c "^\[WARN\]" "$out" 2>/dev/null || echo 0)
  local pass=$(grep -c "^\[PASS\]" "$out" 2>/dev/null || echo 0)
  local info=$(grep -c "^\[INFO\]" "$out" 2>/dev/null || echo 0)
  local score=$(grep -oE "Score: -?[0-9]+" "$out" | head -1 | grep -oE "\-?[0-9]+")
  printf "%-15s pass=%-3s warn=%-3s info=%-3s score=%s\n" \
    "ct${ct}" "$pass" "$fail" "$info" "${score:-?}"
}

header "Docker Bench for Security (CIS Docker Benchmark)"
log "results dir: $OUT_DIR"
log ""

for ct in $(pct list | awk 'NR>1 && $2=="running" {print $1}'); do
  has_docker=$(pct exec "$ct" -- bash -c 'command -v docker >/dev/null && echo yes' 2>/dev/null)
  [[ "$has_docker" != "yes" ]] && continue
  run_bench "$ct"
done

log ""
info "full reports: $OUT_DIR/"
info "list all WARN findings: grep -h '^\[WARN\]' $OUT_DIR/*.log | sort | uniq -c | sort -rn | head -30"
