# Linux Security Kit

Linux/Proxmox 운영 환경에서 보안 CVE를 **진단 → mitigation → 패치**까지 한 번에 처리하기 위한 재사용 키트. 한 호스트에서 검증 끝난 절차를 다음 환경에 빠르게 옮기는 게 목적.

광범위 매칭(Trivy, Grype 등)으로 잡지 못하는 운영 결정·mitigation까지 가져가려고 만든 도구다. 통합 스캐너와는 **보완 관계** — 통합 스캐너 사용은 [`playbooks/95-integration-scanners.md`](playbooks/95-integration-scanners.md) 참조.

## 디렉토리

```
security/
├── README.md                    # 이 파일 (인덱스)
├── cves/                        # CVE별 자료 + 스크립트
│   ├── 2026/
│   │   ├── 2026-31431-copy-fail/
│   │   ├── 2026-35414-splitsshell/
│   │   ├── 2026-32202-ntlm-coercion/
│   │   ├── 2026-5450-glibc-scanf/
│   │   ├── 2026-0861-glibc-memalign/
│   │   ├── 2026-35535-sudo-drop/
│   │   ├── 2026-23113-io-uring-race/
│   │   ├── 2026-31418-netfilter-conntrack/
│   │   ├── 2026-41651-pack2theroot/
│   │   └── 2026-42167-proftpd-sqli/
│   └── 2025/
│       ├── 2024-1086-flipping-pages/
│       └── 2025-9230-openssl-dos/
├── playbooks/                   # 워크플로우 가이드
│   ├── 00-triage-cve.md
│   ├── 10-proxmox-host-patch.md
│   ├── 20-lxc-userspace-patch.md
│   ├── 30-emergency-mitigation.md
│   ├── 90-distro-cheatsheet.md
│   └── 95-integration-scanners.md
├── tools/
│   ├── lib/common.sh            # 배포판 감지 등 공용 함수
│   ├── check-host.sh            # 호스트 일반 진단
│   ├── check-lxc.sh             # LXC 컨테이너 진단
│   ├── scan-all-cves.sh         # 등록된 모든 CVE 일괄 진단
│   └── gen-ansible-inventory.sh # PVE에서 LXC inventory 자동 생성
└── ansible/                     # 다수 호스트·LXC 자동 적용 레이어
    ├── ansible.cfg
    ├── inventory/
    ├── group_vars/
    ├── playbooks/
    │   ├── 01-audit.yml
    │   ├── 02-mitigate.yml
    │   ├── 03-patch.yml
    │   └── 04-configure-auto-updates.yml
    └── roles/                   # kit_sync, cve_mitigate, auto_updates
```

## 빠른 사용법

### 단일 호스트 / 응급 / 일회성 — bash로 직접
```bash
sudo bash tools/check-host.sh                                   # 호스트 스냅샷
sudo bash tools/scan-all-cves.sh                                # CVE 일괄 진단
sudo bash cves/2026/2026-31431-copy-fail/mitigate.sh            # 특정 CVE 응급
```

### 다수 호스트·LXC — Ansible로 일관 적용
```bash
cd ansible/
cp inventory/example-homelab.yml inventory/homelab.yml          # 자기 호스트 채우기
ansible-playbook -i inventory/homelab.yml playbooks/01-audit.yml
ansible-playbook -i inventory/homelab.yml playbooks/02-mitigate.yml -e cve_id=2026-31431-copy-fail
ansible-playbook -i inventory/homelab.yml playbooks/04-configure-auto-updates.yml
```

PVE 호스트에서 LXC inventory 자동 생성:
```bash
ssh prod-pve 'bash -s' < tools/gen-ansible-inventory.sh > ansible/inventory/from-pve.yml
```

자세한 사용법은 [`ansible/README.md`](ansible/README.md).

### 광범위 안전망 — Trivy
```bash
sudo trivy rootfs --severity CRITICAL,HIGH /
```
키트가 등록한 CVE 외에도 매칭. 자세한 통합은 [`playbooks/95-integration-scanners.md`](playbooks/95-integration-scanners.md).

## CVE 인덱스

| ID | 별명 | 컴포넌트 | 영향 | 패치 컷오프 | CVSS |
|---|---|---|---|---|---|
| [CVE-2026-31431](cves/2026/2026-31431-copy-fail/) | Copy Fail | kernel `algif_aead` | LPE → root | 6.18.22 / 6.19.12 / 7.0 | 7.8 |
| [CVE-2026-41651](cves/2026/2026-41651-pack2theroot/) | Pack2TheRoot | PackageKit | 무인증 패키지 설치 → root | PackageKit 1.3.5+ | **8.8** |
| [CVE-2026-5450](cves/2026/2026-5450-glibc-scanf/) | — | glibc `scanf %mc` | heap overflow → RCE | 배포판별 (2026-04 패치 묶음) | **9.8** |
| [CVE-2026-0861](cves/2026/2026-0861-glibc-memalign/) | — | glibc `memalign` | int overflow → heap corruption | CVE-2026-5450과 같이 묶임 | High |
| [CVE-2026-35414](cves/2026/2026-35414-splitsshell/) | SplitSSHell | OpenSSH | CA 인증 우회 → root | OpenSSH 10.3+ | 8.1 |
| [CVE-2026-35535](cves/2026/2026-35535-sudo-drop/) | — | sudo | privilege drop 실패 | 배포판별 advisory | High |
| [CVE-2026-23113](cves/2026/2026-23113-io-uring-race/) | — | kernel `io_uring` | race → kernel panic (DoS) | 6.12.3+ | High |
| [CVE-2026-31418](cves/2026/2026-31418-netfilter-conntrack/) | — | kernel netfilter | helper 처리 결함 | 배포판별 | High |
| [CVE-2026-32202](cves/2026/2026-32202-ntlm-coercion/) | — | SMB / NTLM | zero-click coercion | 배포판별 | — |
| [CVE-2026-42167](cves/2026/2026-42167-proftpd-sqli/) | — | ProFTPD `mod_sql` | SQLi → RCE / 인증 우회 | 배포판별 | High |
| [CVE-2024-1086](cves/2025/2024-1086-flipping-pages/) | Flipping Pages | kernel `nf_tables` | UAF → LPE | 5.15.149+ 등 | 7.8 (KEV) |
| [CVE-2025-9230~32](cves/2025/2025-9230-openssl-dos/) | — | OpenSSL | DoS | 3.0.16 / 3.2.5 / 3.3.4 | High |

각 디렉토리의 `README.md`에 CVE 상세, 진단 방법, mitigation 효과/부작용, 영구 패치 절차가 있음.

## 플레이북

- [00 - 새 CVE 트리아지](playbooks/00-triage-cve.md)
- [10 - Proxmox 호스트 패치](playbooks/10-proxmox-host-patch.md)
- [20 - LXC userspace 패치](playbooks/20-lxc-userspace-patch.md)
- [30 - 응급 Mitigation 모음](playbooks/30-emergency-mitigation.md)
- [90 - 배포판별 패키지 매니저 치트시트](playbooks/90-distro-cheatsheet.md)
- [95 - 오픈소스 통합 스캐너 (Trivy/Vuls/Lynis)](playbooks/95-integration-scanners.md)

## 지원 환경

| 환경 | 진단 | Mitigation | 패치 자동화 |
|---|---|---|---|
| Proxmox VE 8/9 | ✅ | ✅ | 부분 |
| Ubuntu 22.04/24.04/26.04 | ✅ | ✅ | apt 기반 |
| Debian 12/13 | ✅ | ✅ | apt 기반 |
| RHEL/Rocky/Alma 9/10 | ✅ | ✅ | dnf 기반 |
| Arch Linux | ✅ | ✅ | pacman 기반 |
| openSUSE/SUSE | 부분 | 부분 | zypper 기반 |
| LXC (모든 배포판) | ✅ | (호스트단) | 컨테이너 OS 따라감 |

`tools/lib/common.sh`의 `detect_distro()`가 자동 분기하므로 스크립트는 한 번에 모든 환경에서 돈다.

## 새 CVE 등록

1. `cves/<year>/<id>-<slug>/` 디렉토리 생성
2. `README.md`(개요·영향·진단·패치), `detect.sh`(진단), `mitigate.sh`(응급) 작성
3. 이 README 인덱스 표에 한 줄 추가
4. `tools/scan-all-cves.sh`의 `CVES=()` 배열에 detect.sh 경로 한 줄 추가

스크립트는 모두 root 권한 가정. 종료 코드 규약: `0`=안전, `1`=취약, `2`=판단 불가.

## 운영 모델 — 하이브리드

```
┌─ 정기 / 다수 호스트 적용 ────────  Ansible (ansible/playbooks/*.yml)
├─ 응급 / 일회성 / 디버깅 ─────────  bash 키트 (직접 SSH)
├─ 광범위 detect ────────────────  Trivy / Vuls / Grype
└─ 야간 자동 보안 패치 ────────────  unattended-upgrades / dnf-automatic
                                     (playbooks/04로 일괄 셋업)
```

**원칙**: mitigation 로직은 bash `mitigate.sh` 한 벌만 유지. Ansible은 `script:` 모듈로 그대로 호출 — 두 번 작성하지 않음.

## 한계

- 등록 CVE는 **선별 큐레이션**. 매주 수십 건 등록되는 모든 CVE를 다루지 않음.
- 광범위 매칭은 Trivy에 맡기고, 키트는 **운영 결정·mitigation·플레이북** 영역에 집중.
- Windows 호스트는 범위 밖.
