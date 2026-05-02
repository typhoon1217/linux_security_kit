#!/usr/bin/env bash
# CVE-2026-31431 (Copy Fail) — mitigation (no reboot required).
# Blocks autoload of algif_* and af_alg via modprobe install lines.
# Side effects: anything using AF_ALG via the kernel crypto API will fail to load.
# Run --dry-run to preview without writing.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../../../tools/lib/common.sh"

DRY_RUN=no
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=yes
require_root

CONF=/etc/modprobe.d/disable-algif-cve-2026-31431.conf
MODULES=(af_alg algif_aead algif_skcipher algif_hash algif_rng)

header "CVE-2026-31431 mitigation"

if [[ "$DRY_RUN" == yes ]]; then
  info "dry-run: would write to $CONF and unload listed modules"
fi

# ---------- step 1: write conf ----------

CONTENT="# CVE-2026-31431 (Copy Fail) mitigation — applied $(date -Iseconds)
# Blocks autoload of AF_ALG and algif_* on socket(AF_ALG,...) calls.
"
for m in "${MODULES[@]}"; do
  CONTENT+="install $m /bin/false
"
done

if [[ "$DRY_RUN" == yes ]]; then
  printf '%s' "$CONTENT" | sed 's/^/    /'
else
  if [[ -f "$CONF" ]]; then
    info "$CONF already exists — overwriting"
  fi
  printf '%s' "$CONTENT" > "$CONF"
  ok "wrote $CONF"
fi

# ---------- step 2: unload anything currently loaded ----------

LOADED=()
for m in "${MODULES[@]}"; do
  module_loaded "$m" && LOADED+=("$m")
done

if [[ ${#LOADED[@]} -gt 0 ]]; then
  if [[ "$DRY_RUN" == yes ]]; then
    info "would unload: ${LOADED[*]}"
  else
    # algif_* depend on af_alg — unload algif_* first, then af_alg.
    modprobe -r algif_aead algif_skcipher algif_hash algif_rng 2>/dev/null || true
    modprobe -r af_alg 2>/dev/null || true
    STILL=()
    for m in "${MODULES[@]}"; do
      module_loaded "$m" && STILL+=("$m")
    done
    if [[ ${#STILL[@]} -eq 0 ]]; then
      ok "unloaded: ${LOADED[*]}"
    else
      warn "could not unload: ${STILL[*]} — module is in use; reboot will pick up the conf"
      record warn
    fi
  fi
else
  ok "no algif_* / af_alg modules currently loaded"
fi

# ---------- step 3: verify autoload is blocked ----------

if [[ "$DRY_RUN" == yes ]]; then
  info "would test: modprobe algif_aead must fail"
else
  if modprobe algif_aead 2>/dev/null; then
    if module_loaded algif_aead; then
      fail "algif_aead loaded despite mitigation — verify $CONF was written and modprobe.d ordering"
      record vuln
    else
      ok "modprobe returned 0 but module is not loaded — install line redirected, mitigation effective"
    fi
  else
    ok "modprobe algif_aead failed as expected — autoload is blocked"
  fi
fi

log ""
case "$WORST" in
  0) ok "mitigation in place" ;;
  1) warn "mitigation in place but with warnings — see above" ;;
  2) fail "mitigation did not take effect — investigate" ;;
esac

cat <<'NEXT'

Next step: schedule a kernel upgrade to a patched version.
See README.md in this directory for distro-specific fix versions.
NEXT

final_exit
