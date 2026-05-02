#!/usr/bin/env bash
# Common helpers for the Linux Security Kit.
# Source this file from other scripts: . "$(dirname "$0")/lib/common.sh"

set -u

# ---------- output ----------

C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'
[[ -t 1 ]] || { C_RESET=; C_RED=; C_GREEN=; C_YELLOW=; C_BLUE=; C_BOLD=; }

log()    { printf '%s\n' "$*"; }
ok()     { printf '%s[OK]%s %s\n'    "$C_GREEN"  "$C_RESET" "$*"; }
warn()   { printf '%s[WARN]%s %s\n'  "$C_YELLOW" "$C_RESET" "$*"; }
fail()   { printf '%s[VULN]%s %s\n'  "$C_RED"    "$C_RESET" "$*"; }
info()   { printf '%s[INFO]%s %s\n'  "$C_BLUE"   "$C_RESET" "$*"; }
header() { printf '\n%s== %s ==%s\n' "$C_BOLD"   "$*" "$C_RESET"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    fail "this script must run as root (try: sudo $0)"
    exit 2
  fi
}

# ---------- distro detection ----------

# Sets DISTRO_ID, DISTRO_LIKE, DISTRO_VERSION, PKG_MGR.
detect_distro() {
  DISTRO_ID=unknown; DISTRO_LIKE=; DISTRO_VERSION=; PKG_MGR=
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID=${ID:-unknown}
    DISTRO_LIKE=${ID_LIKE:-}
    DISTRO_VERSION=${VERSION_ID:-}
  fi
  case "$DISTRO_ID $DISTRO_LIKE" in
    *debian*|*ubuntu*) PKG_MGR=apt ;;
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*) PKG_MGR=dnf ;;
    *arch*)            PKG_MGR=pacman ;;
    *suse*|*opensuse*) PKG_MGR=zypper ;;
    *)                 PKG_MGR=unknown ;;
  esac
  # Proxmox VE rides on top of Debian — flag separately.
  IS_PROXMOX=no
  [[ -x /usr/bin/pveversion ]] && IS_PROXMOX=yes
}

# ---------- environment classification ----------

# Sets HOST_KIND to one of: proxmox-host, lxc-container, vm-or-bare
detect_host_kind() {
  if [[ -f /proc/1/environ ]] && grep -aqz container=lxc /proc/1/environ; then
    HOST_KIND=lxc-container
  elif [[ "${IS_PROXMOX:-no}" == yes ]]; then
    HOST_KIND=proxmox-host
  else
    HOST_KIND=vm-or-bare
  fi
}

# ---------- kernel comparison ----------

# Compare two version strings using dpkg --compare-versions semantics if available,
# else fall back to sort -V.
# Returns 0 if $1 OP $2.
ver_cmp() {
  local a=$1 op=$2 b=$3
  if command -v dpkg >/dev/null; then
    dpkg --compare-versions "$a" "$op" "$b" && return 0 || return 1
  fi
  case "$op" in
    lt) [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)" == "$a" && "$a" != "$b" ]] ;;
    le) [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)" == "$a" ]] ;;
    eq) [[ "$a" == "$b" ]] ;;
    ge) [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | tail -1)" == "$a" ]] ;;
    gt) [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | tail -1)" == "$a" && "$a" != "$b" ]] ;;
    *) return 2 ;;
  esac
}

# ---------- module check ----------

module_loaded() { lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$1"; }

module_blocked() {
  # True if any modprobe.d file routes the module's install to /bin/false or similar.
  grep -rEhs "^[[:space:]]*install[[:space:]]+$1[[:space:]]+/bin/(false|true)" \
    /etc/modprobe.d/ /lib/modprobe.d/ /run/modprobe.d/ 2>/dev/null | grep -q .
}

# ---------- package version lookup ----------

pkg_version() {
  local p=$1
  case "$PKG_MGR" in
    apt)    dpkg-query -W -f '${Version}' "$p" 2>/dev/null ;;
    dnf)    rpm -q --qf '%{VERSION}-%{RELEASE}' "$p" 2>/dev/null ;;
    pacman) pacman -Q "$p" 2>/dev/null | awk '{print $2}' ;;
    zypper) rpm -q --qf '%{VERSION}-%{RELEASE}' "$p" 2>/dev/null ;;
    *) return 1 ;;
  esac
}

# ---------- summary helpers ----------

# Track a verdict across multiple checks; final exit reflects worst.
WORST=0
record() {
  local verdict=$1
  case "$verdict" in
    ok)   :  ;;
    warn) [[ $WORST -lt 1 ]] && WORST=1 ;;
    vuln) WORST=2 ;;
  esac
}
final_exit() { exit "$WORST"; }
