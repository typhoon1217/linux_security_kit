#!/usr/bin/env bash
# CVE-2026-32202 — mitigation: enforce SMB3 + signing for active CIFS mounts.
# This script does NOT remount; it just emits the recommended mount options
# and audits /etc/fstab for unsafe entries.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

require_root

header "CVE-2026-32202 mitigation guidance"

cat <<'GUIDE'
Recommended mount options for cifs/smb:
    vers=3.1.1,seal,signing=mandatory

Example fstab line:
    //fileserver/share /mnt/share cifs credentials=/etc/cifs.creds,vers=3.1.1,seal,_netdev 0 0

Run this script after editing /etc/fstab to verify nothing falls back to NTLMv1.
GUIDE

if [[ -r /etc/fstab ]]; then
  log ""
  log "fstab review:"
  RISKY=$(grep -E '^[^#]*[[:space:]]cifs[[:space:]]' /etc/fstab | grep -vE 'vers=3' || true)
  if [[ -n "$RISKY" ]]; then
    fail "fstab entries without vers=3 — relay-attack candidates:"
    echo "$RISKY" | sed 's/^/    /'
    record vuln
  else
    ok "no risky CIFS fstab entries"
  fi
fi

log ""
info "permanent fix: upgrade samba/cifs-utils + monitor Microsoft-side advisories for full chain mitigation"
final_exit
