# 20 — LXC 컨테이너 userspace 패치

호스트 커널 패치는 LXC 전부에 한 번에 적용되지만, **userspace는 컨테이너마다 독립**이다. openssl, libc, sudo, openssh, Samba 등은 컨테이너 안의 패키지 매니저가 관리.

## 0. 핵심 점검 명령

호스트에서:

```bash
# 컨테이너 일괄 진단
sudo bash tools/check-lxc.sh
```

각 컨테이너에서 보고하는 핵심:

- 패키지 카탈로그 mtime — 7일 이상이면 노란불, 30일 이상이면 빨간불
- 외부 mirror DNS 해석 가능 여부
- `unattended-upgrades` / `dnf-automatic` 활성 여부

## 1. "0 upgraded" 함정

```
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
```

이 출력은 안전을 의미하지 않는다. **`apt update`가 조용히 실패했을 때도 0이 나온다.** 같이 봐야 할 신호:

```bash
ls -la /var/lib/apt/lists/*Release | head -5         # 카탈로그 언제 받았나
apt-get update 2>&1 | grep -E "Err:|Failed|401"      # 받기 자체에 실패했나
timeout 5 curl -sI http://archive.ubuntu.com/ubuntu/dists/noble/Release  # mirror 응답
```

세 줄 중 하나라도 망가지면 `apt list --upgradable`은 거짓말을 하고 있는 것.

## 2. 격리된 컨테이너의 패치 경로

컨테이너가 사내 VPN/사설 DNS만 보고 외부 mirror에 닿지 않으면:

### 옵션 A — 임시 외부 DNS 추가 (가장 빠름)

```bash
pct exec $vmid -- bash -c '
  cp /etc/resolv.conf /etc/resolv.conf.before
  echo "nameserver 8.8.8.8" >> /etc/resolv.conf
  apt update
  apt full-upgrade -y
  cp /etc/resolv.conf.before /etc/resolv.conf
'
```

격리 정책 영구 변경 없이 작업 시간만큼만 외부 접근. 끝나면 원복.

### 옵션 B — 호스트에 apt-cacher-ng (정석)

```bash
# 호스트
apt install -y apt-cacher-ng
systemctl enable --now apt-cacher-ng
```

컨테이너 안에서 `Acquire::HTTP::Proxy "http://<host-ip>:3142"` 설정 후 apt update. 이게 격리 정책과 가장 잘 맞는다.

### 옵션 C — 컨테이너 OS template 갱신

운영 결함이 큰 컨테이너는 차라리 새 template으로 교체하는 게 빠를 수 있다. 데이터 디렉토리만 backup, 새 템플릿으로 redeploy.

## 3. 자동 업데이트 에이전트 설치

Ubuntu/Debian:

```bash
apt install -y unattended-upgrades
systemctl enable --now unattended-upgrades.service
```

RHEL/Rocky:

```bash
dnf install -y dnf-automatic
systemctl enable --now dnf-automatic.timer
```

배포판 기본 설정은 보안 업데이트만 자동 적용하도록 되어 있어 안전. `/etc/apt/apt.conf.d/50unattended-upgrades`에서 알림 이메일과 reboot 정책만 조정.

## 4. 컨테이너 내부 부팅 결함 — DHCP가 안 도는 경우

가끔 LXC 컨테이너 부팅 시 DHCP 클라이언트가 자동으로 안 도는 경우가 있다. 증상:

```
$ ip a show eth0
eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
    inet6 fe80::.../64 scope link
# IPv4 주소 없음
```

원인: netplan/systemd-networkd 설정 누락. 임시 해결:

```bash
pct exec $vmid -- dhclient -v eth0
```

영구 해결: 컨테이너 안에 netplan yaml 생성:

```yaml
# /etc/netplan/50-dhcp.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
```

`netplan apply` 후 재부팅 시에도 자동.

## 5. 사후 검증

```bash
sudo bash tools/check-lxc.sh
```

세 가지가 다 보여야 정상:

1. 모든 컨테이너 패키지 카탈로그 1~7일 이내
2. 외부 mirror 해석 가능 (옵션 B를 골랐다면 호스트 mirror)
3. `unattended-upgrades`/`dnf-automatic` 모두 active

## 6. 패치 후 서비스 재시작 — 잊기 쉬운 단계

`apt upgrade`만으로는 메모리에 올라간 라이브러리가 갱신 안 된다. 특히 OpenSSL 같은 공유 라이브러리는:

```bash
# Debian/Ubuntu
needrestart -r a

# 일반
systemctl list-units --state=running | awk '{print $1}' | \
  xargs -I{} sh -c 'systemctl status {} 2>/dev/null | grep -qE "deleted|outdated" && echo {}'
```

해당 서비스 재시작하지 않으면 OpenSSL DoS 같은 패치는 사실상 적용 안 된 상태로 남는다.
