#!/usr/bin/env bash
# CVE-2025-9230~9232 — there is no in-process mitigation for OpenSSL DoS.
# This script restarts long-running services after an OpenSSL upgrade so
# they pick up the new library.
# Use --dry-run to preview.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

DRY_RUN=no
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=yes
require_root

header "CVE-2025-9230~9232 — restart libssl-linked services"

if command -v needrestart >/dev/null; then
  if [[ "$DRY_RUN" == yes ]]; then
    needrestart -r l 2>&1 | sed 's/^/    /' | head -40
  else
    needrestart -r a -q
    ok "needrestart applied"
  fi
else
  CANDIDATES=(nginx apache2 httpd postfix dovecot openvpn sshd haproxy mysql mariadb postgresql)
  for svc in "${CANDIDATES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      if [[ "$DRY_RUN" == yes ]]; then
        info "would restart: $svc"
      else
        systemctl restart "$svc" && ok "restarted $svc" || warn "$svc restart failed"
      fi
    fi
  done
fi

log ""
info "do not skip this step — apt/dnf upgrade alone leaves the old library in process memory"
final_exit
