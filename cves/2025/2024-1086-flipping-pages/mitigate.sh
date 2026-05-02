#!/usr/bin/env bash
# CVE-2024-1086 — mitigation: disable unprivileged user namespaces.
# Side effects: rootless Docker, Chrome sandbox, snap, Flatpak partially break.
# Use --dry-run to preview.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

DRY_RUN=no
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=yes
require_root

header "CVE-2024-1086 mitigation: disable unprivileged userns"

CONF=/etc/sysctl.d/99-disable-userns-cve-2024-1086.conf
LINE='kernel.unprivileged_userns_clone=0'

if [[ "$DRY_RUN" == yes ]]; then
  info "would write: $LINE → $CONF"
  info "would apply: sysctl -w $LINE"
else
  echo "$LINE" > "$CONF"
  ok "wrote $CONF"
  sysctl -w kernel.unprivileged_userns_clone=0 >/dev/null
  ok "applied at runtime"
fi

cat <<'WARNS'

Verify nothing important breaks:
  - rootless Docker / Podman
  - Chrome / Firefox sandbox
  - snap / Flatpak applications
  - bubblewrap-based tools (e.g. flatpak-run, sandbox-run)

If any of those are needed, revert with:
  rm /etc/sysctl.d/99-disable-userns-cve-2024-1086.conf
  sysctl -w kernel.unprivileged_userns_clone=1
WARNS

final_exit
