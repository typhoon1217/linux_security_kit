# Defense Stack Audit — Lynis + ssh-audit + Docker Bench

This playbook complements `scan-all-cves.sh` with three open-source auditors that cover the non-CVE side of security posture: system hardening, sshd algorithm strength, and Docker daemon best practices.

## Tools

| Tool | Scope | Install |
|---|---|---|
| **Lynis** | 200+ system hardening controls (CIS/NIST/PCI-DSS aligned) | `apt install lynis` |
| **ssh-audit** | sshd kex/cipher/mac/hostkey strength, CVE-aware | `apt install ssh-audit` or `pip install ssh-audit` |
| **Docker Bench for Security** | CIS Docker Benchmark, daemon + container best practices | docker run (auto-pulled) |

All three are wrapped by `tools/run-*.sh` for one-command execution across host + LXCs.

## Quick run

```bash
cd /root/security
bash tools/run-lynis.sh         # ~5 min on host + 11 LXCs
bash tools/run-ssh-audit.sh     # ~30 sec
bash tools/run-docker-bench.sh  # ~3 min per LXC with docker
```

Full reports land in `/root/security-audit-results/{lynis,ssh-audit,docker-bench}/`.

## Reading the results

### Lynis
- **Hardening index**: 0–100 score per host. >80 = good, 60–80 = improve, <60 = work needed.
- Suggestions are listed at the bottom of each `*.log`. Each links to a Lynis test ID (e.g. `KRNL-5820`) — search lynis docs for fix.
- Common high-impact suggestions: kernel sysctl hardening (KRNL-6000), audit daemon (ACCT-9622), AIDE/Tripwire (FINT-4350), USB storage block.

### ssh-audit
- `fail` = algorithm with known weakness (e.g. SHA1, CBC modes). Should be 0.
- `warn` = legacy algorithm, accept but consider removing.
- Server policy match: confirm sshd is not advertising weak kex/cipher.

### Docker Bench
- `[WARN]` lines = each is a CIS Docker Benchmark failure. Group by line to spot the same finding across containers.
- High-priority: 1.x (host config), 2.x (daemon config), 4.x (container images), 5.x (container runtime).
- Note: many WARNs in single-host homelab environments are accept-and-document (e.g. 2.5 — auditd on docker.service).

## What this stack does NOT cover

- **External attack surface**: what's reachable from outside the LAN. Use `nmap` + external port scan separately.
- **Web app auth strength**: 2FA, brute-force protection, session security. Manual review or specialized tools (e.g. OWASP ZAP, Nuclei).
- **Runtime container behavior**: process anomalies inside containers. Add Falco for runtime EDR.
- **Network IDS**: malicious payloads on the wire. Suricata/Zeek territory.
- **Backup redundancy**: see `playbooks/42-offsite-backup.md`.

## Frequency

- Lynis + ssh-audit: monthly minimum, after any sshd_config or kernel change
- Docker Bench: after docker engine upgrades or compose stack changes
- Diff between runs is the actionable signal — improvement vs regression

## Integration with existing scanners

These three sit above the CVE layer. Recommended order in a full audit:

1. `tools/scan-all-cves.sh` — patch-state of curated CVEs
2. `trivy fs --scanners vuln /` — broad CVE
3. `tools/run-lynis.sh` — system hardening posture
4. `tools/run-ssh-audit.sh` — auth surface strength
5. `tools/run-docker-bench.sh` — container daemon posture
