#!/usr/bin/env bash
# CVE-2026-32202 — diagnostic (Linux exposure surface).
# Linux is mostly affected as an SMB client; this script flags client-side risk.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

header "CVE-2026-32202 (NTLM coercion) — diagnostic"

SAMBA=$(pkg_version samba 2>/dev/null || pkg_version samba-libs 2>/dev/null)
CIFS=$(pkg_version cifs-utils 2>/dev/null)
log "  samba: ${SAMBA:-not installed}"
log "  cifs-utils: ${CIFS:-not installed}"

CIFS_MOUNTS=$(mount -t cifs 2>/dev/null | wc -l)
if [[ "$CIFS_MOUNTS" -gt 0 ]]; then
  warn "$CIFS_MOUNTS active CIFS mount(s) — review for trust boundary"
  mount -t cifs | sed 's/^/    /'
  record warn
else
  info "no active CIFS mounts"
fi

NTLM_ENABLED=no
if [[ -r /etc/samba/smb.conf ]]; then
  if grep -qiE "^[[:space:]]*ntlm auth[[:space:]]*=" /etc/samba/smb.conf; then
    log "  smb.conf ntlm auth setting:"
    grep -iE "^[[:space:]]*ntlm auth" /etc/samba/smb.conf | sed 's/^/    /'
  fi
fi

if [[ -d /etc/sssd ]]; then
  warn "SSSD configuration present — check for NTLM auth in AD setup"
  record warn
fi

log ""
case "$WORST" in
  0) ok "no obvious NTLM client exposure" ;;
  *) warn "exposure surface present — see above and confirm Samba/CIFS patch level for your distro" ;;
esac
final_exit
