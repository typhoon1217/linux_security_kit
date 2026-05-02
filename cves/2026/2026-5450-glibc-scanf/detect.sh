#!/usr/bin/env bash
# CVE-2026-5450 (glibc scanf %mc heap overflow) — diagnostic.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

header "CVE-2026-5450 (glibc scanf %mc) — diagnostic"

VER=$(ldd --version 2>/dev/null | head -1 | awk '{print $NF}')
log "  glibc runtime: ${VER:-unknown}"

PATCHED=warn
case "$DISTRO_ID" in
  ubuntu|debian)
    PKG=$(pkg_version libc6)
    log "  libc6 package: ${PKG:-not installed}"
    case "$DISTRO_ID:$DISTRO_VERSION" in
      ubuntu:24.04) ver_cmp "$PKG" ge "2.39-0ubuntu8.7" && PATCHED=ok ;;
      debian:13)    ver_cmp "$PKG" ge "2.41-12+deb13u3" && PATCHED=ok ;;
      debian:12)    ver_cmp "$PKG" ge "2.36-9+deb12u9"  && PATCHED=ok ;;
    esac
    ;;
  rhel|rocky|almalinux|centos)
    if rpm -q --changelog glibc 2>/dev/null | grep -qi "CVE-2026-5450"; then
      PATCHED=ok
    fi
    ;;
  arch)
    PKG=$(pkg_version glibc)
    log "  glibc package: ${PKG:-not installed}"
    ver_cmp "$PKG" ge "2.41-2" && PATCHED=ok
    ;;
esac

case "$PATCHED" in
  ok)   ok "glibc patched against CVE-2026-5450" ;;
  warn) warn "glibc patch state indeterminate — verify changelog manually"; record warn ;;
  *)    fail "glibc below patch cutoff for $DISTRO_ID $DISTRO_VERSION"; record vuln ;;
esac

# Library staleness check — services may still hold old glibc in memory.
log ""
log "  services using deleted libc6 (need restart):"
if command -v needrestart >/dev/null; then
  needrestart -b 2>/dev/null | grep -E "NEEDRESTART-SVC" | head -10 | sed 's/^/    /' || echo "    (none reported)"
else
  for pid in /proc/[0-9]*; do
    p=$(basename "$pid")
    [[ -r "$pid/maps" ]] || continue
    if grep -q "libc.so.* (deleted)" "$pid/maps" 2>/dev/null; then
      cmd=$(tr '\0' ' ' < "$pid/comm" 2>/dev/null)
      log "    pid $p ($cmd) — running with old libc"
    fi
  done | head -10
fi

case "$WORST" in
  0) ok "not exposed to CVE-2026-5450" ;;
  1) warn "review distro changelog or upgrade libc" ;;
  2) fail "vulnerable — upgrade glibc and restart all services" ;;
esac
final_exit
