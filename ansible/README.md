# Ansible Layer — 하이브리드 운영

bash 키트는 그대로 두고, Ansible로 **다수 호스트·LXC에 일관되게 적용**하는 레이어. mitigation 로직을 두 번 작성하지 않기 위해 Ansible은 `cves/<id>/mitigate.sh`를 그대로 호출한다.

## 운영 모델

```
┌────────────────────────────────────────────────────────┐
│  정기 / 다수 호스트     →  Ansible playbook            │
│  응급 / 일회성 / 디버깅 →  bash 키트 (직접 SSH)        │
│  detect 광범위           →  Trivy (Ansible 안에서 호출) │
└────────────────────────────────────────────────────────┘
```

원칙:

- **mitigate.sh는 한 벌만**. Ansible은 `script:` 모듈로 호출.
- **inventory는 환경별로 분리**. `--limit`으로 격리.
- **`--check` 없이 적용 금지**. 항상 dry-run으로 점검 후 적용.

## 디렉토리

```
ansible/
├── README.md                    # 이 파일
├── ansible.cfg                  # 프로젝트 기본 설정
├── inventory/
│   ├── example-homelab.yml      # 홈랩 inventory 예시 (복사해서 사용)
│   └── example-work.yml         # 회사 inventory 예시
├── group_vars/
│   └── all.yml                  # 전체 공통 변수
├── playbooks/
│   ├── 01-audit.yml             # 모든 대상에 scan-all-cves + check-host
│   ├── 02-mitigate.yml          # 특정 CVE mitigate (extra-vars로 지정)
│   ├── 03-patch.yml             # OS 보안 패치 + 선택적 재부팅
│   └── 04-configure-auto-updates.yml  # unattended-upgrades / dnf-automatic 셋업
└── roles/
    ├── kit_sync/                # 호스트에 키트 파일 동기화
    ├── cve_mitigate/            # mitigate.sh 호출 wrapper (idempotent)
    └── auto_updates/            # 자동 보안 패치 에이전트 설치
```

## 첫 셋업 (5분)

```bash
# 1) Ansible 설치 (제어 머신)
sudo pacman -S ansible    # Arch
sudo apt install ansible  # Debian/Ubuntu

# 2) inventory 복사 후 자기 호스트 채우기
cp inventory/example-homelab.yml inventory/homelab.yml
$EDITOR inventory/homelab.yml

# 3) 연결 점검
ansible -i inventory/homelab.yml all -m ping

# 4) 첫 audit
ansible-playbook -i inventory/homelab.yml playbooks/01-audit.yml
```

## 시나리오별 사용법

### 시나리오 A — 새 CVE 권고가 떴다
```bash
# 영향 평가
ansible-playbook -i inventory/work.yml playbooks/01-audit.yml

# 응급 mitigation 적용 (특정 CVE 한정)
ansible-playbook -i inventory/work.yml playbooks/02-mitigate.yml \
  -e cve_id=2026-31431-copy-fail

# OS 패치 + 호스트별 재부팅 (rolling)
ansible-playbook -i inventory/work.yml playbooks/03-patch.yml --check  # 먼저 dry-run
ansible-playbook -i inventory/work.yml playbooks/03-patch.yml
```

### 시나리오 B — 야간 자동 패치 셋업
```bash
ansible-playbook -i inventory/homelab.yml playbooks/04-configure-auto-updates.yml
```
이후 unattended-upgrades / dnf-automatic이 매일 자동 적용.

### 시나리오 C — 단일 호스트 응급 처치 (Ansible 거치지 않음)
```bash
ssh prod-host 'cd /root/security && bash cves/2026/2026-31431-copy-fail/mitigate.sh'
```
빠른 길. 끝나면 inventory에 등록된 다른 호스트도 Ansible로 적용.

## LXC 자동 inventory 생성

PVE 호스트에서 LXC 전체를 inventory에 자동 등록하려면:

```bash
ssh prod-pve 'bash -s' < tools/gen-ansible-inventory.sh > inventory/from-pve.yml
ansible-playbook -i inventory/from-pve.yml playbooks/01-audit.yml
```

`tools/gen-ansible-inventory.sh`가 `pct list`를 읽어 inventory YAML을 생성. PVE 호스트도 같은 inventory에 들어감.

## 알아둘 함정

- **`become: true`는 host 정의에 둘 것**. role 안에 흩어두면 디버깅 헬.
- **`gather_facts: false`로 시작 권장**. 불필요한 facts 수집 시간 큼. 필요한 role에서만 켜기.
- **bash mitigate.sh의 exit code를 신뢰**. `failed_when:`을 임의로 풀어두면 실패가 묻힘.
- **inventory 파일은 git에 커밋**, vault 데이터는 별도. SSH key path는 변수로.

## Trivy 통합

`02-mitigate.yml`의 `pre_tasks`에서 Trivy를 먼저 돌리고 결과 JSON에서 CVE를 추출해 conditional mitigate를 거는 패턴이 가능. 본 MVP에는 없음 — 호스트별 Trivy 결과 파싱 ROI가 환경에 따라 큼. 확장 시 `roles/trivy_scan/`을 추가.

## 한계

- AWX/Tower 같은 UI는 안 씀. CLI만으로 충분.
- 멀티 클러스터/멀티 region은 inventory를 더 쪼개면 됨.
- Windows 호스트는 본 키트 범위 밖.
