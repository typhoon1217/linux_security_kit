#!/usr/bin/env bash
# CVE-2026-41651 (Pack2TheRoot, PackageKit TOCTOU) — diagnostic.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

header "CVE-2026-41651 (Pack2TheRoot) — diagnostic"

PKG=$(pkg_version packagekit 2>/dev/null || pkg_version PackageKit 2>/dev/null)
log "  PackageKit package: ${PKG:-not installed}"

if [[ -z "$PKG" ]]; then
  ok "PackageKit not installed — not exposed"
  final_exit
fi

# Extract just the upstream version (strip distro suffix).
VER=$(echo "$PKG" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
log "  upstream version: $VER"

if ver_cmp "$VER" ge "1.3.5"; then
  ok "PackageKit $VER is patched (≥ 1.3.5)"
else
  fail "PackageKit $VER is below patch cutoff (1.3.5)"
  record vuln
fi

# Daemon active?
ACTIVE=$(systemctl is-active packagekit 2>/dev/null || echo unknown)
case "$ACTIVE" in
  active)   warn "packagekit.service is active — exposure live"; record warn ;;
  inactive) info "packagekit.service inactive — exposure smaller, but socket-activation may wake it" ;;
  failed)   info "packagekit.service failed state" ;;
  *)        info "packagekit.service status: $ACTIVE" ;;
esac

# D-Bus activation
DBUS_FILE=/usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service
[[ -r "$DBUS_FILE" ]] && info "D-Bus auto-activation enabled at $DBUS_FILE"

# Headless heuristic
if ! systemctl list-units --type=target 2>/dev/null | grep -q graphical.target; then
  info "no graphical.target — likely headless server, consider masking PackageKit"
fi

case "$WORST" in
  0) ok "not exposed to CVE-2026-41651" ;;
  1) warn "review needed" ;;
  2) fail "exposed — apply mitigate.sh, then upgrade PackageKit to ≥ 1.3.5" ;;
esac
final_exit
