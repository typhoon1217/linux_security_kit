#!/usr/bin/env bash
# Wrap Lynis system audit and run it across the host plus every running LXC.
# Lynis is a 200+ control hardening auditor (CIS/NIST/PCI-DSS aligned).
# Output: short summary on stdout; full reports saved to OUT_DIR.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib/common.sh"

require_root

OUT_DIR=${OUT_DIR:-/root/security-audit-results/lynis}
mkdir -p "$OUT_DIR"

ensure_lynis() {
  local where="$1"
  if [[ "$where" == "host" ]]; then
    command -v lynis >/dev/null || apt-get install -y lynis >/dev/null 2>&1
  else
    pct exec "$where" -- bash -c 'command -v lynis >/dev/null || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y lynis >/dev/null 2>&1)'
  fi
}

run_lynis() {
  local label="$1"
  local cmd="$2"
  local out="$OUT_DIR/${label}.log"
  $cmd lynis audit system --quick --no-colors --quiet > "$out" 2>&1 || true
  local score=$(grep -oE "Hardening index : \[[0-9]+\]" "$out" | grep -oE "[0-9]+")
  local suggestions=$(grep -c "^\s*\*" "$out" 2>/dev/null || echo 0)
  local warnings=$(grep -c "^Warning" "$out" 2>/dev/null || echo 0)
  printf "%-15s score=%-4s suggestions=%-3s warnings=%-3s\n" \
    "$label" "${score:-?}" "$suggestions" "$warnings"
}

header "Lynis system audit"
log "results dir: $OUT_DIR"
log ""

log "[host]"
ensure_lynis host
run_lynis "host" ""

log ""
log "[LXC running]"
for ct in $(pct list | awk 'NR>1 && $2=="running" {print $1}'); do
  ensure_lynis "$ct"
  run_lynis "ct${ct}" "pct exec $ct --"
done

log ""
info "full reports: $OUT_DIR/"
info "view a single host: less $OUT_DIR/host.log"
info "list all suggestions: grep -h '^  \*' $OUT_DIR/*.log | sort -u"
