#!/usr/bin/env bash
# CVE-2026-42167 (ProFTPD mod_sql SQLi) — diagnostic.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

header "CVE-2026-42167 (ProFTPD mod_sql SQLi) — diagnostic"

if ! command -v proftpd >/dev/null 2>&1 \
   && ! pkg_version proftpd-basic >/dev/null 2>&1 \
   && ! pkg_version proftpd >/dev/null 2>&1; then
  ok "ProFTPD not installed — not exposed"
  final_exit
fi

PKG=$(pkg_version proftpd-basic 2>/dev/null || pkg_version proftpd 2>/dev/null)
log "  ProFTPD package: ${PKG:-unknown}"

# mod_sql availability
if proftpd -l 2>/dev/null | grep -q mod_sql; then
  log "  mod_sql: built-in"
  HAS_MOD_SQL=yes
else
  HAS_MOD_SQL=no
fi
for f in /etc/proftpd/proftpd.conf /etc/proftpd/conf.d/*.conf /etc/proftpd/modules.conf; do
  [[ -r "$f" ]] || continue
  if grep -qE "^[[:space:]]*LoadModule.*mod_sql" "$f"; then
    HAS_MOD_SQL=yes
    log "  mod_sql LoadModule in $f"
  fi
done

if [[ "$HAS_MOD_SQL" == yes ]]; then
  warn "mod_sql is enabled — exposure surface present"
  record warn
else
  ok "mod_sql not loaded — exposure greatly reduced"
fi

# Daemon state
ACTIVE=$(systemctl is-active proftpd 2>/dev/null || echo unknown)
log "  proftpd.service: $ACTIVE"

# External exposure
LISTEN_21=$(ss -tlnp 2>/dev/null | grep -E ":21\b" | head -3)
if [[ -n "$LISTEN_21" ]]; then
  log "  port 21 listeners:"
  echo "$LISTEN_21" | sed 's/^/    /'
  if echo "$LISTEN_21" | grep -qE "0\.0\.0\.0:21|\*:21"; then
    fail "FTP listening on all interfaces — open Internet exposure highly likely"
    record vuln
  fi
fi

case "$WORST" in
  0) ok "not obviously exposed" ;;
  1) warn "review proftpd config and apply mitigate.sh" ;;
  2) fail "exposed — apply mitigate.sh and upgrade ProFTPD" ;;
esac
final_exit
