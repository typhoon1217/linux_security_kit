#!/usr/bin/env bash
# CVE-2024-1086 (Flipping Pages) — diagnostic.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

KVER=$(uname -r)
KMAJOR=$(echo "$KVER" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

header "CVE-2024-1086 (Flipping Pages) — diagnostic"
log "  kernel: $KVER"

# Mainline cutoffs (best-effort; distro backports vary)
PATCHED=no
if   [[ "$KMAJOR" == 5.15.* ]]; then ver_cmp "$KMAJOR" ge "5.15.149" && PATCHED=yes
elif [[ "$KMAJOR" == 6.1.*  ]]; then ver_cmp "$KMAJOR" ge "6.1.76"  && PATCHED=yes
elif [[ "$KMAJOR" == 6.6.*  ]]; then ver_cmp "$KMAJOR" ge "6.6.15"  && PATCHED=yes
elif ver_cmp "$KMAJOR" ge "6.7.3"; then PATCHED=yes
fi

if [[ "$PATCHED" == yes ]]; then
  ok "kernel $KMAJOR is past mainline patch cutoff"
else
  warn "kernel $KMAJOR is below the mainline cutoff — check distro-specific backport"
  record warn
fi

# Secondary signal: unprivileged user namespace.
USERNS=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo unknown)
log "  unprivileged_userns_clone: $USERNS"
if [[ "$USERNS" == "1" ]]; then
  if [[ "$PATCHED" == no ]]; then
    fail "unprivileged user namespaces enabled AND kernel may be unpatched — exploit conditions met"
    record vuln
  else
    info "unprivileged user namespaces enabled — patched kernel mitigates"
  fi
fi

# CISA KEV reminder
log ""
info "CISA KEV listed — actively exploited by ransomware groups (RansomHub, Akira)"

case "$WORST" in
  0) ok "not obviously exposed" ;;
  1) warn "review distro changelog for CVE-2024-1086 backport" ;;
  2) fail "exposed — apply mitigate.sh and prioritize kernel upgrade" ;;
esac
final_exit
