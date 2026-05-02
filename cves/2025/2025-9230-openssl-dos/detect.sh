#!/usr/bin/env bash
# CVE-2025-9230 / 9231 / 9232 (OpenSSL DoS) — diagnostic.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

header "CVE-2025-9230~9232 (OpenSSL DoS) — diagnostic"

VER=$(openssl version 2>/dev/null | awk '{print $2}')
log "  openssl runtime: ${VER:-not found}"

if [[ -z "$VER" ]]; then
  warn "openssl binary not found — skipping runtime check"
  record warn
else
  PATCHED=no
  if   [[ "$VER" == 3.0.* ]]; then ver_cmp "$VER" ge "3.0.16" && PATCHED=yes
  elif [[ "$VER" == 3.2.* ]]; then ver_cmp "$VER" ge "3.2.5"  && PATCHED=yes
  elif [[ "$VER" == 3.3.* ]]; then ver_cmp "$VER" ge "3.3.4"  && PATCHED=yes
  elif [[ "$VER" == 3.[4-9]* ]] || [[ "$VER" == [4-9].* ]]; then PATCHED=yes
  fi
  if [[ "$PATCHED" == yes ]]; then
    ok "openssl $VER is past patch cutoff"
  else
    fail "openssl $VER is below patch cutoff (need 3.0.16 / 3.2.5 / 3.3.4)"
    record vuln
  fi
fi

# Detect services likely linked against the old library.
log ""
log "  long-running services that link libssl (may need restart after upgrade):"
if command -v needrestart >/dev/null; then
  needrestart -b 2>/dev/null | grep -E "^NEEDRESTART" | sed 's/^/    /' || true
else
  for svc in nginx apache2 httpd postfix openvpn sshd haproxy; do
    systemctl is-active --quiet "$svc" 2>/dev/null && log "    $svc"
  done
fi

case "$WORST" in
  0) ok "openssl up to date" ;;
  1) warn "review needed" ;;
  2) fail "vulnerable — upgrade openssl and restart linked services" ;;
esac
final_exit
