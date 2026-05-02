#!/usr/bin/env bash
# CVE-2026-41651 — mitigation: stop + mask PackageKit until upgraded.
# Side effects: GUI package managers (GNOME Software, KDE Discover) stop working.
# CLI tools (apt, dnf, pacman) are unaffected.
# Use --dry-run to preview.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

DRY_RUN=no
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=yes
require_root

header "CVE-2026-41651 mitigation: mask packagekit.service"

if ! systemctl list-unit-files 2>/dev/null | grep -q "^packagekit.service"; then
  ok "packagekit.service not present — nothing to mitigate"
  final_exit
fi

if [[ "$DRY_RUN" == yes ]]; then
  info "would: systemctl stop packagekit.service"
  info "would: systemctl mask packagekit.service"
else
  systemctl stop packagekit.service 2>/dev/null && ok "stopped packagekit.service" \
    || warn "stop failed (already inactive?)"
  systemctl mask packagekit.service 2>/dev/null && ok "masked packagekit.service" \
    || { fail "mask failed"; record vuln; }
fi

cat <<'NOTES'

GUI package management may now show errors — that is expected.
CLI tools (apt, dnf, pacman) keep working normally.

After upgrading PackageKit to ≥ 1.3.5, revert with:
  systemctl unmask packagekit.service
  systemctl start packagekit.service
NOTES

final_exit
