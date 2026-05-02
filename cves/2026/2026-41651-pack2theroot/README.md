# CVE-2026-41651 — Pack2TheRoot (PackageKit TOCTOU)

| | |
|---|---|
| 별명 | Pack2TheRoot |
| 컴포넌트 | PackageKit (D-Bus 시스템 데몬) |
| 클래스 | TOCTOU race → unauthorized package install/remove → root |
| CVSS | **8.8 (High)** |
| 공개 | 2026-04-27 (Deutsche Telekom Security 보고) |
| 영향 버전 | PackageKit 1.0.2 ~ 1.3.4 (12년치) |
| 픽스 버전 | PackageKit **1.3.5** 이상 |

## 무엇이 문제인가

PackageKit가 transaction flag 검증과 실제 설치 사이에 **TOCTOU(time-of-check time-of-use) race**를 가진다. authorization 단계에서는 무해한 dummy 패키지로 검사 → 통과되면 그 직후에 악성 패키지로 swap → root 권한으로 설치/제거 실행. unprivileged user가 패스워드 없이 임의 시스템 패키지를 install/remove할 수 있어 root 등극 직행.

## 영향 범위 (벤더 검증된 기본 설치)

- Ubuntu Desktop 18.04 (EOL), 24.04, 26.04 LTS beta
- Ubuntu Server 22.04 ~ 24.04 LTS
- Debian Desktop Trixie 13.4
- Rocky Linux Desktop 10.1
- Fedora 43 Desktop / Server
- 그 외 GNOME Software, KDE Discover 백엔드를 쓰는 모든 배포판

## 공격 표면이 큰 이유

PackageKit는 D-Bus 위에서 시스템 데몬으로 돌면서 GUI 패키지 매니저(GNOME Software, KDE Discover, Snap Store 일부)에 backend를 제공. 데스크톱 환경에서 거의 항상 활성. 헤드리스 서버에는 보통 미설치지만, 일부 배포판은 GUI 컴포넌트 일부와 같이 끌려와 남아있는 경우 있음.

## 진단

PackageKit 버전 + 데몬 활성 여부:

```bash
pkcon --version 2>/dev/null
dpkg-query -W -f '${Version}' packagekit       # apt
rpm -q PackageKit                              # dnf
pacman -Q packagekit                           # pacman

# 데몬 활성?
systemctl is-active packagekit
```

활성 + 1.3.5 미만이면 노출. 헤드리스 서버에서 미사용이면 우선 데몬 정지가 빠른 방법.

## Mitigation

데몬 즉시 정지 + 비활성화. 데스크톱 GUI 패키지 매니저를 못 쓰게 되지만 CLI(`apt`, `dnf`)는 영향 없음.

```bash
systemctl stop packagekit
systemctl disable packagekit
systemctl mask packagekit  # 다른 서비스가 의존성으로 깨우는 것도 차단
```

## 영구 패치

```bash
# Debian/Ubuntu
apt update && apt install -y packagekit

# RHEL/Rocky/Alma/Fedora
dnf update -y PackageKit

# Arch
pacman -Syu packagekit
```

업그레이드 후 `systemctl restart packagekit`. mask했다면 `systemctl unmask packagekit && systemctl start packagekit`로 복구.

## 자료

- [Telekom Security 권고 — 원본](https://github.security.telekom.com/2026/04/pack2theroot-linux-local-privilege-escalation.html)
- [SecurityWeek — Pack2TheRoot 분석](https://www.securityweek.com/easily-exploitable-pack2theroot-linux-vulnerability-leads-to-root-access/)
- [BleepingComputer 보도](https://www.bleepingcomputer.com/news/security/new-pack2theroot-flaw-gives-hackers-root-linux-access/)
- [Ubuntu USN — CVE-2026-41651](https://ubuntu.com/security/CVE-2026-41651)
