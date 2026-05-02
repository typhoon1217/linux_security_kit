# 10 — Proxmox 호스트 커널 패치 워크플로우

LXC 컨테이너는 호스트 커널을 공유하므로, 호스트 커널 한 번이 컨테이너 전부의 운명을 결정한다. 핵심은 **(1) repo가 정상인지 확인 → (2) mitigation 먼저 → (3) 커널 업그레이드 → (4) 재부팅 → (5) 검증** 순서.

## 0. 사전 조건

- root SSH 접근
- 디스크 여유 5GB 이상 (`df -h /boot /var`)
- 짧은 다운타임 가능 (재부팅 1~3분)

## 1. APT repo 정상 확인

```bash
# 어떤 후보가 보이는지
apt-cache policy proxmox-kernel-6.17 proxmox-default-kernel

# 후보가 현재 설치 버전과 같으면 repo가 막힘
ls /etc/apt/sources.list.d/
apt update 2>&1 | grep -E "Err:|401|Cannot"
```

자주 보이는 패턴:

- **enterprise repo만 활성 + 구독 없음** → 401 에러. `pve-enterprise.sources`를 `.disabled`로 옮기고 `pve-no-subscription` 추가.
- **ceph repo도 enterprise** → 같은 401. ceph 미사용이면 비활성화.

`pve-no-subscription` repo 정의:

```bash
cat > /etc/apt/sources.list.d/pve-no-subscription.sources <<'EOF'
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF

apt update
```

## 2. 응급 mitigation 적용 (재부팅 불필요)

CVE에 따라 `cves/<id>/mitigate.sh`를 적용. 예시 (Copy Fail):

```bash
bash cves/2026/2026-31431-copy-fail/mitigate.sh
```

이 단계에서 공격 표면은 닫힘. 커널 업그레이드는 일정 잡고 진행해도 됨.

## 3. 커널 선택

```bash
apt-cache policy proxmox-default-kernel proxmox-kernel-6.17 proxmox-kernel-7.0
```

결정 기준:

- **같은 라인 유지(권장)**: `6.17.x` → `6.17.13-6` 같은 minor 업. ZFS, NIC 드라이버 호환성 안전.
- **메이저 점프(7.0)**: PVE 메타패키지가 권장하는 라인이지만 검증 시간이 더 든다.

같은 라인 유지가 안전하지만 default 메타패키지가 자동으로 7.0을 끌고 들어오는 걸 막으려면:

```bash
apt-mark hold proxmox-default-kernel
apt install -y proxmox-kernel-6.17
```

## 4. 전체 업그레이드 + 부트 갱신

```bash
DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y \
  -o Dpkg::Options::='--force-confdef' \
  -o Dpkg::Options::='--force-confold'
proxmox-boot-tool refresh
```

`update-grub`은 새 커널과 이전 커널 둘 다 menuentry에 등록한다. 새 커널이 default, 이전 커널은 fallback.

이 시점에서 `dpkg -l | grep proxmox-kernel`로 새 커널 패키지가 들어왔는지 확인. 실행 중인 커널은 **여전히 이전 버전**임 — 재부팅 후에야 활성.

## 5. 재부팅 (SSH 친화적)

SSH 응답을 깔끔하게 받고 끊기는 패턴:

```bash
systemd-run --on-active=5sec --unit=manual-reboot.timer systemctl reboot
```

원격에서 polling으로 부팅 완료 확인:

```bash
for i in $(seq 1 30); do
  ssh prod-host 'uname -r; uptime' 2>/dev/null && break
  sleep 5
done
```

## 6. 검증

```bash
ssh prod-host '
  uname -r                           # 새 커널 확인
  pveversion                          # PVE 버전 확인
  cat /etc/modprobe.d/disable-*.conf  # mitigation 유지 확인
  pct list                            # 컨테이너 자동 시작 확인
'
```

`tools/check-host.sh`와 `tools/scan-all-cves.sh`를 호스트에 올려 다시 한 번 일괄 점검.

## 7. 사후 정리

- `apt-mark unhold proxmox-default-kernel` (메타패키지 hold 해제)
- 운영 모니터링 30분 — ZFS, 네트워크, 컨테이너 상태 정상인지
- 운영 결함이 발견되면 GRUB에서 fallback 커널로 부팅해 롤백

## 자주 보는 함정

- **"0 upgraded"의 거짓 안심**: `apt update`가 실패해도 `apt list --upgradable`은 0을 반환한다. `/var/lib/apt/lists/*Release`의 mtime을 같이 봐야 정확.
- **`grub-efi-amd64 meta-package not installed` 경고**: PVE의 boot 구성에서 정보성. update-grub 자체가 정상이면 부팅에 문제 없음.
- **Hold 풀어둔 채 다음 업그레이드 시 메이저 점프**: hold 해제 시점을 의도해서 잡을 것.
