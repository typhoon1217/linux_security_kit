#!/usr/bin/env bash
# Run ssh-audit against the host and every running LXC's sshd.
# ssh-audit checks key exchange algorithms, ciphers, MACs, host key types
# against CVE-aware policy database.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib/common.sh"

require_root

OUT_DIR=${OUT_DIR:-/root/security-audit-results/ssh-audit}
mkdir -p "$OUT_DIR"

if ! command -v ssh-audit >/dev/null; then
  log "installing ssh-audit (apt or pip)..."
  apt-get install -y ssh-audit >/dev/null 2>&1 || pip install --break-system-packages ssh-audit >/dev/null 2>&1
fi

if ! command -v ssh-audit >/dev/null; then
  fail "ssh-audit not available — install manually"
  final_exit
fi

audit_target() {
  local label="$1"
  local target="$2"
  local out="$OUT_DIR/${label}.log"
  ssh-audit --no-colors "$target" > "$out" 2>&1 || true
  local fail_count=$(grep -cE '\(fail\)' "$out" 2>/dev/null || echo 0)
  local warn_count=$(grep -cE '\(warn\)' "$out" 2>/dev/null || echo 0)
  printf "%-15s target=%-22s fail=%-3s warn=%-3s\n" \
    "$label" "$target" "$fail_count" "$warn_count"
}

header "ssh-audit (sshd algorithm strength)"
log "results dir: $OUT_DIR"
log ""

log "[host]"
audit_target "host" "127.0.0.1:22"

log ""
log "[LXC running]"
for ct in $(pct list | awk 'NR>1 && $2=="running" {print $1}'); do
  ip=$(pct exec "$ct" -- ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
  [[ -z "$ip" ]] && continue
  audit_target "ct${ct}" "${ip}:22"
done

log ""
info "full reports: $OUT_DIR/"
info "view: less $OUT_DIR/host.log"
