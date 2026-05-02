#!/usr/bin/env bash
# CVE-2026-35414 (SplitSSHell) — mitigation.
# Disables certificate-based auth temporarily by commenting out TrustedUserCAKeys.
# Use --dry-run to preview.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

DRY_RUN=no
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=yes
require_root

header "CVE-2026-35414 mitigation"

CHANGED=()
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
  [[ -r "$f" ]] || continue
  if grep -qE "^[[:space:]]*TrustedUserCAKeys" "$f"; then
    if [[ "$DRY_RUN" == yes ]]; then
      info "would comment out TrustedUserCAKeys in $f"
    else
      cp "$f" "$f.cve-2026-35414.bak"
      sed -i -E 's|^([[:space:]]*TrustedUserCAKeys.*)$|# CVE-2026-35414 disabled: \1|' "$f"
      ok "patched $f (backup at $f.cve-2026-35414.bak)"
      CHANGED+=("$f")
    fi
  fi
done

if [[ ${#CHANGED[@]} -gt 0 ]] && [[ "$DRY_RUN" == no ]]; then
  if sshd -t 2>&1 | tee /tmp/sshd-test.out | grep -q .; then
    fail "sshd config test produced output — review /tmp/sshd-test.out before reload"
    record warn
  else
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || \
      warn "could not reload sshd — restart the service manually"
    ok "sshd reloaded — certificate auth temporarily disabled"
  fi
elif [[ "$DRY_RUN" == no ]]; then
  ok "no TrustedUserCAKeys directives found — no mitigation needed"
fi

log ""
info "permanent fix: upgrade openssh-server to ≥ 10.3, then revert by removing the '# CVE-2026-35414 disabled:' prefix"

final_exit
