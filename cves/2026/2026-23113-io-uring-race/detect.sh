#!/usr/bin/env bash
# CVE-2026-23113 (io_uring race) — diagnostic.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

KVER=$(uname -r)
KMAJOR=$(echo "$KVER" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

header "CVE-2026-23113 (io_uring race) — diagnostic"
log "  kernel: $KVER"

# Mainline cutoff: 6.12.3
PATCHED=no
if   [[ "$KMAJOR" == 6.12.* ]]; then ver_cmp "$KMAJOR" ge "6.12.3" && PATCHED=yes
elif ver_cmp "$KMAJOR" ge "6.13"; then PATCHED=yes
fi

if [[ "$PATCHED" == yes ]]; then
  ok "kernel $KMAJOR is past mainline patch cutoff (6.12.3)"
else
  warn "kernel $KMAJOR is below cutoff — check distro backport"
  record warn
fi

# Mitigation state
DISABLED=$(sysctl -n kernel.io_uring_disabled 2>/dev/null || echo unknown)
case "$DISABLED" in
  2) ok "io_uring fully disabled (kernel.io_uring_disabled=2) — exposure closed" ;;
  1) warn "io_uring restricted to root (=1) — partial mitigation"; record warn ;;
  0) [[ "$PATCHED" == yes ]] && info "io_uring enabled — patched kernel mitigates" \
       || { fail "io_uring enabled AND kernel unpatched"; record vuln; } ;;
  unknown) info "kernel.io_uring_disabled sysctl not present — older kernel" ;;
esac

# Multi-tenant signal
if pct list 2>/dev/null | tail -n +2 | grep -q .; then
  info "Proxmox host with LXCs — multi-tenant exposure, prioritize patching"
elif command -v kubelet >/dev/null 2>&1; then
  info "Kubernetes node detected — multi-tenant exposure"
fi

case "$WORST" in
  0) ok "not exposed to CVE-2026-23113" ;;
  1) warn "review backport state and mitigation" ;;
  2) fail "exposed — apply mitigate.sh now, schedule kernel upgrade" ;;
esac
final_exit
