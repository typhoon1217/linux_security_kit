#!/usr/bin/env bash
# CVE-2026-35414 (SplitSSHell) — diagnostic.
# Exit codes: 0=safe, 1=vulnerable, 2=cannot determine.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

header "CVE-2026-35414 (SplitSSHell) — diagnostic"

VER=$(ssh -V 2>&1 | sed -E 's/.*OpenSSH_([0-9.]+).*/\1/')
log "  openssh: $VER"

if [[ -z "$VER" ]] || ! [[ "$VER" =~ ^[0-9]+\.[0-9]+ ]]; then
  warn "could not parse OpenSSH version"
  record warn
elif ver_cmp "$VER" ge "10.3"; then
  ok "OpenSSH $VER is patched (≥ 10.3)"
else
  fail "OpenSSH $VER is below the fix cutoff (10.3)"
  record vuln
fi

USES_CA=no
if [[ -r /etc/ssh/sshd_config ]]; then
  if grep -qE "^[[:space:]]*TrustedUserCAKeys" /etc/ssh/sshd_config; then
    USES_CA=yes
  fi
  if grep -rqE "^[[:space:]]*TrustedUserCAKeys" /etc/ssh/sshd_config.d/ 2>/dev/null; then
    USES_CA=yes
  fi
fi

if [[ "$USES_CA" == yes ]]; then
  log "  TrustedUserCAKeys is configured — certificate-based auth in use"
  if [[ "$WORST" -ge 2 ]]; then
    fail "exposure is real on this host"
  fi
else
  info "TrustedUserCAKeys not configured — exposure limited even if version is old"
fi

# principals= option in authorized_keys is the actual abuse vector.
PRINC_FOUND=0
for f in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
  [[ -r "$f" ]] || continue
  if grep -qE 'principals=' "$f" 2>/dev/null; then
    PRINC_FOUND=$((PRINC_FOUND+1))
    log "  $f uses principals= option"
  fi
done
[[ "$PRINC_FOUND" -gt 0 ]] && warn "$PRINC_FOUND authorized_keys file(s) use principals= — review for comma misuse"

log ""
case "$WORST" in
  0) ok "not exposed to CVE-2026-35414" ;;
  1) warn "review needed" ;;
  2) fail "vulnerable — upgrade openssh to ≥ 10.3" ;;
esac
final_exit
