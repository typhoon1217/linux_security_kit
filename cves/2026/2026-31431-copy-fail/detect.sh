#!/usr/bin/env bash
# CVE-2026-31431 (Copy Fail) — diagnostic.
# Exit codes: 0=safe, 1=vulnerable, 2=cannot determine.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root
detect_distro

KVER=$(uname -r)

header "CVE-2026-31431 (Copy Fail) — diagnostic"
log "  distro: $DISTRO_ID $DISTRO_VERSION"
log "  kernel: $KVER"

# ---------- step 1: kernel version vs. fix cutoff ----------

# Strip distro suffix (e.g. "6.17.13-6-pve" -> "6.17.13").
KMAJOR=$(echo "$KVER" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

is_kernel_patched() {
  case "$DISTRO_ID" in
    debian)
      # Debian trixie: 6.12.85-1+, bookworm: 6.1.170-1+
      ver_cmp "$KMAJOR" ge "6.12.85" && return 0
      ver_cmp "$KMAJOR" ge "6.1.170" && [[ "$KMAJOR" == 6.1.* ]] && return 0
      ;;
    ubuntu)
      # Ubuntu HWE/GA varies; safer to also accept mainline cutoffs.
      ;;
    arch)
      ver_cmp "$KMAJOR" ge "6.19.12" && return 0
      ;;
    rhel|rocky|almalinux|centos)
      # RHEL kernels report as 4.18 / 5.14 with backports — version alone is insufficient.
      return 2
      ;;
  esac
  # Proxmox VE: proxmox-kernel-6.17 line patched at 6.17.13-5.
  if [[ "${IS_PROXMOX:-no}" == yes ]] && [[ "$KVER" == *-pve ]]; then
    if [[ "$KMAJOR" == 6.17.* ]]; then
      local rev
      rev=$(echo "$KVER" | sed -E 's/^6\.17\.([0-9]+)-([0-9]+)-pve.*/\1.\2/')
      ver_cmp "$rev" ge "13.5" && return 0
      return 1
    fi
    [[ "$KMAJOR" == 7.0.* ]] && return 0
  fi
  # Mainline cutoffs.
  ver_cmp "$KMAJOR" ge "6.19.12" && return 0
  ver_cmp "$KMAJOR" ge "6.18.22" && [[ "$KMAJOR" == 6.18.* ]] && return 0
  ver_cmp "$KMAJOR" ge "7.0" && return 0
  return 1
}

if is_kernel_patched; then
  ok "kernel $KMAJOR is at or past the patch cutoff for this distro"
  KERNEL_VERDICT=ok
else
  case $? in
    2) warn "kernel patch status indeterminate on $DISTRO_ID ($KMAJOR) — check changelog manually"; record warn; KERNEL_VERDICT=warn ;;
    *) fail "kernel $KMAJOR is below the patch cutoff for $DISTRO_ID"; record vuln; KERNEL_VERDICT=vuln ;;
  esac
fi

# ---------- step 2: modprobe blacklist ----------

BLOCKED_ALL=yes
for m in af_alg algif_aead algif_skcipher algif_hash algif_rng; do
  if module_blocked "$m"; then
    ok "$m autoload blocked via modprobe.d"
  else
    BLOCKED_ALL=no
    log "  $m: not blocked"
  fi
done

# ---------- step 3: live load attempt ----------

PRE_LOADED=$(lsmod 2>/dev/null | awk '$1=="algif_aead" {print $1}')
modprobe algif_aead 2>/dev/null || true
POST_LOADED=$(lsmod 2>/dev/null | awk '$1=="algif_aead" {print $1}')

if [[ -z "$PRE_LOADED" ]] && [[ -z "$POST_LOADED" ]] && [[ "$BLOCKED_ALL" == yes ]]; then
  ok "live load attempt blocked — mitigation is effective"
  MITIGATION_VERDICT=ok
elif [[ -n "$POST_LOADED" ]]; then
  if [[ "$KERNEL_VERDICT" == ok ]]; then
    info "algif_aead loaded — harmless on patched kernel"
    MITIGATION_VERDICT=ok
  else
    fail "algif_aead loadable AND kernel unpatched — actively exploitable"
    record vuln
    MITIGATION_VERDICT=vuln
  fi
else
  warn "live load attempt did not produce a definitive result"
  record warn
  MITIGATION_VERDICT=warn
fi

# ---------- summary ----------

log ""
header "summary"
log "  kernel patch:  $KERNEL_VERDICT"
log "  mod block:     $([[ "$BLOCKED_ALL" == yes ]] && echo yes || echo partial/no)"
log "  live test:     $MITIGATION_VERDICT"
case "$WORST" in
  0) ok   "not exposed to CVE-2026-31431" ;;
  1) warn "review needed — see above" ;;
  2) fail "exposed to CVE-2026-31431 — apply mitigate.sh now, schedule kernel upgrade" ;;
esac

final_exit
