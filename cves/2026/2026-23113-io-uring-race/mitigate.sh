#!/usr/bin/env bash
# CVE-2026-23113 — mitigation: disable io_uring entirely.
# Side effects: programs that use io_uring fall back to epoll/aio. Performance may drop.
# Use --dry-run to preview.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

DRY_RUN=no
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=yes
require_root

header "CVE-2026-23113 mitigation: disable io_uring"

CONF=/etc/sysctl.d/99-disable-io-uring-cve-2026-23113.conf

if [[ "$DRY_RUN" == yes ]]; then
  info "would write: kernel.io_uring_disabled=2 → $CONF"
  info "would apply: sysctl -w kernel.io_uring_disabled=2"
else
  echo 'kernel.io_uring_disabled=2' > "$CONF"
  ok "wrote $CONF"
  if sysctl -w kernel.io_uring_disabled=2 >/dev/null 2>&1; then
    ok "applied at runtime"
  else
    warn "sysctl write failed — kernel may not support kernel.io_uring_disabled (older than 6.6)"
    record warn
  fi
fi

cat <<'NOTES'

Verify nothing important breaks:
  - MariaDB / MySQL with io_uring storage engine
  - Nginx io_uring backend (ngx_io_uring)
  - high-performance io frameworks (e.g. fio --ioengine=io_uring)

To revert:
  rm /etc/sysctl.d/99-disable-io-uring-cve-2026-23113.conf
  sysctl -w kernel.io_uring_disabled=0
NOTES

final_exit
