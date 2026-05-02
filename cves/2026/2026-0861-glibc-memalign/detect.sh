#!/usr/bin/env bash
# CVE-2026-0861 (glibc memalign integer overflow) — diagnostic.
# Patch state typically tracks CVE-2026-5450; reuse the same logic.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

header "CVE-2026-0861 (glibc memalign) — diagnostic"

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
    if rpm -q --changelog glibc 2>/dev/null | grep -qi "CVE-2026-0861"; then
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
  ok)   ok "glibc patched against CVE-2026-0861" ;;
  warn) warn "indeterminate — verify changelog manually"; record warn ;;
  *)    fail "glibc below patch cutoff"; record vuln ;;
esac

case "$WORST" in
  0) ok "not exposed to CVE-2026-0861" ;;
  *) warn "see above; mitigate is the same as CVE-2026-5450 (upgrade + restart all services)" ;;
esac
final_exit
