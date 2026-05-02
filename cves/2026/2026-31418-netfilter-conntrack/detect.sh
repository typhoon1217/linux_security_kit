#!/usr/bin/env bash
# CVE-2026-31418 (netfilter conntrack helper) — diagnostic.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root

header "CVE-2026-31418 (netfilter conntrack) — diagnostic"

# Active helpers — kernel-built-in + auto-assigned
HELPER_AUTO=$(sysctl -n net.netfilter.nf_conntrack_helper 2>/dev/null || echo unknown)
log "  net.netfilter.nf_conntrack_helper: $HELPER_AUTO"

LOADED=$(lsmod 2>/dev/null | awk '/^nf_conntrack/ {print $1}' | tr '\n' ' ')
log "  conntrack-related modules loaded: ${LOADED:-none}"

if [[ "$HELPER_AUTO" == "1" ]]; then
  warn "auto helper assignment is enabled — exposure surface present"
  record warn
elif [[ "$HELPER_AUTO" == "0" ]]; then
  ok "auto helper assignment disabled — exposure reduced"
fi

# helper modules?
HELPER_MODS=$(lsmod 2>/dev/null | awk '/^nf_conntrack_(ftp|tftp|sip|irc|h323|amanda|pptp)/ {print $1}' | tr '\n' ' ')
if [[ -n "$HELPER_MODS" ]]; then
  log "  protocol helper modules loaded: $HELPER_MODS"
  warn "specific helpers loaded — review whether they are required"
  record warn
else
  ok "no protocol helper modules loaded"
fi

# Forwarding role amplifies exposure
FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [[ "$FORWARD" == "1" ]]; then
  info "ip_forward=1 — this host routes packets, exposure is broader"
fi

case "$WORST" in
  0) ok "minimal conntrack helper exposure" ;;
  *) warn "review helper config or apply mitigate.sh + kernel patch" ;;
esac
final_exit
