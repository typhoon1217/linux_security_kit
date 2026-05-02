#!/usr/bin/env bash
# CVE-2026-42167 — mitigation: stop ProFTPD or disable mod_sql.
# Use --dry-run to preview.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

DRY_RUN=no
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=yes
require_root

header "CVE-2026-42167 mitigation"

if ! systemctl list-unit-files 2>/dev/null | grep -q "^proftpd.service"; then
  ok "proftpd.service not present — nothing to mitigate"
  final_exit
fi

cat <<'CHOICES'
Pick one path. Default of this script is the safest (stop + mask the daemon).
For production, comment out mod_sql lines instead and restart proftpd.

This script does the safest path automatically. To do option B manually,
edit /etc/proftpd/proftpd.conf (and conf.d/*.conf) to comment LoadModule mod_sql.
CHOICES

if [[ "$DRY_RUN" == yes ]]; then
  info "would: systemctl stop proftpd.service"
  info "would: systemctl mask proftpd.service"
else
  systemctl stop proftpd.service 2>/dev/null && ok "stopped proftpd.service" \
    || warn "stop failed"
  systemctl mask proftpd.service 2>/dev/null && ok "masked proftpd.service" \
    || { fail "mask failed"; record vuln; }
fi

cat <<'NEXT'

After upgrading ProFTPD to a patched version, revert with:
  systemctl unmask proftpd.service
  systemctl start proftpd.service
NEXT

final_exit
