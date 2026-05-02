#!/usr/bin/env bash
# CVE-2026-35535 (sudo privilege drop failure) — diagnostic.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

header "CVE-2026-35535 (sudo privilege drop) — diagnostic"

PKG=$(pkg_version sudo)
log "  sudo package: ${PKG:-not installed}"

if [[ -z "$PKG" ]]; then
  warn "sudo not installed — skipping"
  final_exit
fi

PATCHED=warn
case "$DISTRO_ID:$DISTRO_VERSION" in
  ubuntu:24.04)  ver_cmp "$PKG" ge "1.9.15p5-3ubuntu5.24.04.3" && PATCHED=ok ;;
  debian:13)     ver_cmp "$PKG" ge "1.9.16p2-1+deb13u1"        && PATCHED=ok ;;
  rhel:10*|rocky:10*|almalinux:10*) ver_cmp "$PKG" ge "1.9.17-1" && PATCHED=ok ;;
  arch:*) PATCHED=ok ;;
esac

# Fallback: scan rpm changelog for the CVE id.
if [[ "$PATCHED" != ok ]] && command -v rpm >/dev/null; then
  if rpm -q --changelog sudo 2>/dev/null | grep -qi "CVE-2026-35535"; then
    PATCHED=ok
  fi
fi

case "$PATCHED" in
  ok)   ok "sudo patched against CVE-2026-35535" ;;
  warn) warn "indeterminate — check distro advisory"; record warn ;;
  *)    fail "sudo below patch cutoff"; record vuln ;;
esac

# Sudoers risk surface
if [[ -r /etc/sudoers ]]; then
  NOPASS=$(grep -hE "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE "^#" | wc -l)
  if [[ "$NOPASS" -gt 0 ]]; then
    info "$NOPASS NOPASSWD line(s) in sudoers — wider blast radius if exploited"
  fi
fi

case "$WORST" in
  0) ok "not exposed to CVE-2026-35535" ;;
  *) warn "upgrade sudo via your package manager" ;;
esac
final_exit
