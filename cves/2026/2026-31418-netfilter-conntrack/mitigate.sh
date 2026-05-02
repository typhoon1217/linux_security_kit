#!/usr/bin/env bash
# CVE-2026-31418 — mitigation: disable automatic conntrack helper assignment.
# Side effects: protocols that need helpers (FTP active, SIP, IRC DCC, etc.) may break.
# Use --dry-run to preview.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

DRY_RUN=no
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=yes
require_root

header "CVE-2026-31418 mitigation: disable auto conntrack helpers"

CONF=/etc/sysctl.d/99-conntrack-helper-cve-2026-31418.conf

if [[ "$DRY_RUN" == yes ]]; then
  info "would write: net.netfilter.nf_conntrack_helper=0 → $CONF"
  info "would apply: sysctl -w net.netfilter.nf_conntrack_helper=0"
else
  echo 'net.netfilter.nf_conntrack_helper=0' > "$CONF"
  ok "wrote $CONF"
  if sysctl -w net.netfilter.nf_conntrack_helper=0 >/dev/null 2>&1; then
    ok "applied at runtime"
  else
    warn "sysctl write failed — module may not be loaded"
    record warn
  fi
fi

cat <<'NOTES'

If you legitimately need a helper (e.g. FTP active mode), enable it explicitly per rule:

  nftables example:
    ct helper "ftp" { type "ftp" protocol tcp; }
    add rule inet filter input ct helper "ftp" accept

To revert globally:
  rm /etc/sysctl.d/99-conntrack-helper-cve-2026-31418.conf
  sysctl -w net.netfilter.nf_conntrack_helper=1
NOTES

final_exit
