#!/usr/bin/env bash
# Generic host security snapshot.
# Lists kernel, distro, attack-surface modules, package manager state.
# Does NOT decide patched/vulnerable for specific CVEs — call cves/<id>/detect.sh for that.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib/common.sh"

require_root
detect_distro
detect_host_kind

header "host"
log "  hostname:   $(hostname)"
log "  distro:     $DISTRO_ID $DISTRO_VERSION (like: ${DISTRO_LIKE:-none})"
log "  pkg mgr:    $PKG_MGR"
log "  kind:       $HOST_KIND"
log "  kernel:     $(uname -r)"
log "  uname -v:   $(uname -v)"

header "boot config sanity"
if [[ "$HOST_KIND" == proxmox-host ]]; then
  log "  pveversion: $(pveversion 2>/dev/null | head -1)"
  log "  installed kernels:"
  dpkg -l 2>/dev/null | awk '/^ii.*proxmox-kernel-[0-9]/ {print "    "$2" "$3}' | sort -u
fi
log "  default boot entry:"
if command -v bootctl >/dev/null 2>&1; then
  bootctl 2>/dev/null | grep -E "default|selected" | sed 's/^/    /' || true
fi
[[ -f /etc/default/grub ]] && grep -E "^GRUB_DEFAULT" /etc/default/grub | sed 's/^/    /'

header "AF_ALG / algif_* attack surface"
for m in af_alg algif_aead algif_skcipher algif_hash algif_rng; do
  if module_loaded "$m"; then
    if module_blocked "$m"; then
      warn "$m loaded but install-line routes to /bin/false (blocked on next load)"
    else
      fail "$m loaded and not blocked"
      record vuln
    fi
  else
    if module_blocked "$m"; then
      ok "$m not loaded and autoload is blocked"
    else
      warn "$m not loaded but autoloads on socket(AF_ALG, ...) — consider blocking"
      record warn
    fi
  fi
done

header "package update channel"
case "$PKG_MGR" in
  apt)
    log "  sources active:"
    ls -la /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list \
      /etc/apt/sources.list 2>/dev/null | awk '{print "    "$NF}'
    log "  last successful apt update:"
    stat -c '    %y  %n' /var/lib/apt/lists/lock 2>/dev/null || true
    log "  upgradable packages:"
    apt list --upgradable 2>/dev/null | tail -n +2 | wc -l | sed 's/^/    /'
    ;;
  dnf)
    log "  enabled repos:"
    dnf repolist enabled 2>/dev/null | tail -n +2 | sed 's/^/    /'
    log "  upgradable packages:"
    dnf check-update -q 2>/dev/null | grep -c '\.' | sed 's/^/    /'
    ;;
  pacman)
    log "  configured repos:"
    awk '/^\[/{print "    "$0}' /etc/pacman.conf
    log "  upgradable packages (skip if no checkupdates):"
    command -v checkupdates >/dev/null && checkupdates 2>/dev/null | wc -l | sed 's/^/    /'
    ;;
  zypper)
    log "  enabled repos:"
    zypper -q lr -E 2>/dev/null | sed 's/^/    /'
    ;;
  *) warn "unknown pkg manager — skip update channel check" ;;
esac

header "automatic security update agent"
if systemctl list-unit-files 2>/dev/null | grep -qE "(unattended-upgrades|dnf-automatic|reflector).service"; then
  for s in unattended-upgrades dnf-automatic.timer dnf-automatic-install.timer; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then
      ok "$s active"
    elif systemctl list-unit-files 2>/dev/null | grep -q "^$s"; then
      warn "$s installed but not active"
      record warn
    fi
  done
else
  warn "no automatic security update agent installed"
  record warn
fi

header "ssh config quickscan"
if [[ -r /etc/ssh/sshd_config ]]; then
  for setting in "PermitRootLogin" "PasswordAuthentication" "Protocol"; do
    val=$(grep -iE "^[[:space:]]*$setting" /etc/ssh/sshd_config | head -1)
    [[ -n "$val" ]] && log "    $val"
  done
fi

log ""
case "$WORST" in
  0) ok   "host snapshot complete — no obvious red flags" ;;
  1) warn "host snapshot complete — review the warnings above" ;;
  2) fail "host snapshot complete — vulnerabilities present, see above" ;;
esac
final_exit
