#!/usr/bin/env bash
# Run every registered CVE detect.sh against this host and aggregate the verdicts.
# Exit codes: 0=all clean, 1=at least one warning, 2=at least one vulnerable.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
. "$HERE/lib/common.sh"

require_root

# Registered CVEs — add new entries here when adding cves/<year>/<id>/.
CVES=(
  "$ROOT/cves/2026/2026-31431-copy-fail/detect.sh"
  "$ROOT/cves/2026/2026-35414-splitsshell/detect.sh"
  "$ROOT/cves/2026/2026-32202-ntlm-coercion/detect.sh"
  "$ROOT/cves/2026/2026-5450-glibc-scanf/detect.sh"
  "$ROOT/cves/2026/2026-0861-glibc-memalign/detect.sh"
  "$ROOT/cves/2026/2026-35535-sudo-drop/detect.sh"
  "$ROOT/cves/2026/2026-23113-io-uring-race/detect.sh"
  "$ROOT/cves/2026/2026-31418-netfilter-conntrack/detect.sh"
  "$ROOT/cves/2026/2026-41651-pack2theroot/detect.sh"
  "$ROOT/cves/2026/2026-42167-proftpd-sqli/detect.sh"
  "$ROOT/cves/2025/2024-1086-flipping-pages/detect.sh"
  "$ROOT/cves/2025/2025-9230-openssl-dos/detect.sh"
)

declare -A VERDICT

for d in "${CVES[@]}"; do
  ID=$(basename "$(dirname "$d")")
  if [[ ! -x "$d" ]]; then
    chmod +x "$d" 2>/dev/null
  fi
  if [[ -r "$d" ]]; then
    log ""
    log "==================================================="
    log "running: $ID"
    log "==================================================="
    bash "$d"
    EC=$?
    case $EC in
      0) VERDICT[$ID]=ok ;;
      1) VERDICT[$ID]=vuln; record vuln ;;
      2) VERDICT[$ID]=warn; record warn ;;
      *) VERDICT[$ID]=err;  record warn ;;
    esac
  else
    VERDICT[$ID]="missing"
    record warn
  fi
done

log ""
header "scan summary"
for id in "${!VERDICT[@]}"; do
  v=${VERDICT[$id]}
  case "$v" in
    ok)      ok      "$id" ;;
    warn)    warn    "$id (review needed)" ;;
    vuln)    fail    "$id (vulnerable)" ;;
    missing) warn    "$id (detect.sh missing)" ;;
    err)     warn    "$id (detect.sh error)" ;;
  esac
done

log ""
case "$WORST" in
  0) ok   "no registered CVE flagged this host" ;;
  1) warn "warnings present — manual review needed" ;;
  2) fail "at least one CVE flagged — apply mitigate.sh and schedule patches" ;;
esac

log ""
info "for broader matching beyond this curated list, run Trivy or Grype:"
info "  trivy rootfs --severity CRITICAL,HIGH /"
info "  see playbooks/95-integration-scanners.md"

final_exit
