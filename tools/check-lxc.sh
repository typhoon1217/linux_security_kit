#!/usr/bin/env bash
# LXC container security snapshot.
# Run on the Proxmox host; iterates all containers and reports per-container findings.
# Highlights:
#   - shared host kernel (LPE patches happen at host level)
#   - userspace package staleness (apt list catalog age, security upgrades)
#   - DNS / external mirror reachability
#   - unattended-upgrades presence
#
# Exit codes: 0=all clean, 1=warnings, 2=at least one container vulnerable.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib/common.sh"

require_root

if ! command -v pct >/dev/null; then
  fail "pct not found — this script must run on a Proxmox VE host"
  exit 2
fi

CTS=$(pct list 2>/dev/null | awk 'NR>1 {print $1}')
if [[ -z "$CTS" ]]; then
  info "no containers found"
  exit 0
fi

HOST_KVER=$(uname -r)
header "host kernel (shared by all LXCs): $HOST_KVER"

for v in $CTS; do
  STATUS=$(pct status "$v" 2>/dev/null | awk '{print $2}')
  HOST=$(pct config "$v" 2>/dev/null | awk '/^hostname:/ {print $2}')
  UNPRIV=$(pct config "$v" 2>/dev/null | awk '/^unprivileged:/ {print $2}')
  header "CT $v ($HOST) — status=$STATUS unprivileged=${UNPRIV:-0}"

  if [[ "$STATUS" != "running" ]]; then
    info "stopped — skipping live checks"
    continue
  fi

  # Catalog age
  CATALOG_AGE=$(pct exec "$v" -- bash -c '
    if [[ -d /var/lib/apt/lists ]]; then
      ls -t /var/lib/apt/lists/*Release 2>/dev/null | head -1 | xargs -r stat -c "%Y" 2>/dev/null
    elif [[ -d /var/cache/yum ]] || [[ -d /var/cache/dnf ]]; then
      stat -c "%Y" /var/cache/dnf 2>/dev/null || stat -c "%Y" /var/cache/yum 2>/dev/null
    fi
  ' 2>/dev/null)
  NOW=$(date +%s)
  if [[ -n "$CATALOG_AGE" ]] && [[ "$CATALOG_AGE" =~ ^[0-9]+$ ]]; then
    AGE_DAYS=$(( (NOW - CATALOG_AGE) / 86400 ))
    if [[ $AGE_DAYS -gt 30 ]]; then
      fail "package catalog is ${AGE_DAYS}d old — security info likely stale"
      record vuln
    elif [[ $AGE_DAYS -gt 7 ]]; then
      warn "package catalog is ${AGE_DAYS}d old"
      record warn
    else
      ok "package catalog ${AGE_DAYS}d old"
    fi
  else
    warn "could not read package catalog age"
    record warn
  fi

  # External mirror reachability
  pct exec "$v" -- bash -c '
    if command -v getent >/dev/null; then
      timeout 3 getent hosts archive.ubuntu.com >/dev/null 2>&1 \
        || timeout 3 getent hosts deb.debian.org   >/dev/null 2>&1 \
        || timeout 3 getent hosts mirrorlist.centos.org >/dev/null 2>&1 \
        || timeout 3 getent hosts mirror.archlinux.org   >/dev/null 2>&1
    fi
  ' && ok "DNS resolves a known mirror" || { warn "container cannot resolve a known package mirror"; record warn; }

  # Upgrade summary (apt/dnf/pacman)
  pct exec "$v" -- bash -c '
    if command -v apt >/dev/null; then
      SEC=$(apt list --upgradable 2>/dev/null | grep -ci security)
      ALL=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)
      echo "  apt upgradable: total=$ALL  security=$SEC"
    elif command -v dnf >/dev/null; then
      ALL=$(dnf check-update -q 2>/dev/null | grep -c "\." || echo 0)
      SEC=$(dnf updateinfo list security -q 2>/dev/null | wc -l)
      echo "  dnf upgradable: total=$ALL  security=$SEC"
    elif command -v pacman >/dev/null; then
      command -v checkupdates >/dev/null && echo "  pacman upgradable: $(checkupdates 2>/dev/null | wc -l)"
    fi
  ' 2>/dev/null

  # Auto-update agent
  pct exec "$v" -- bash -c '
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
      echo "  unattended-upgrades: active"
    elif systemctl is-active --quiet dnf-automatic.timer 2>/dev/null; then
      echo "  dnf-automatic: active"
    else
      echo "  no auto-update agent active"
    fi
  ' 2>/dev/null
done

log ""
case "$WORST" in
  0) ok   "all containers look healthy" ;;
  1) warn "review warnings above" ;;
  2) fail "at least one container is exposed — see above" ;;
esac
final_exit
