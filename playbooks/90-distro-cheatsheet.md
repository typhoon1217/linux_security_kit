# 90 — 배포판별 패키지 매니저 치트시트

배포판이 달라도 의도는 같다. 같은 작업을 각 매니저에서 어떻게 표현하는지.

## 카탈로그 갱신 + 보안 업그레이드

| 작업 | apt (Debian/Ubuntu/PVE) | dnf (RHEL/Rocky/Alma) | pacman (Arch) | zypper (SUSE) |
|---|---|---|---|---|
| 카탈로그 갱신 | `apt update` | `dnf check-update` | `pacman -Sy` | `zypper refresh` |
| 보안만 업그레이드 | `apt-get install --only-upgrade <pkg>` (자동 분류 한정) | `dnf upgrade --security` | (구분 없음, `pacman -Syu`로 전체) | `zypper patch` |
| 전체 업그레이드 | `apt full-upgrade -y` | `dnf upgrade -y` | `pacman -Syu` | `zypper update` |

## 패키지 정보 조회

| 작업 | apt | dnf | pacman | zypper |
|---|---|---|---|---|
| 설치 버전 | `dpkg-query -W -f '${Version}' <pkg>` | `rpm -q <pkg>` | `pacman -Q <pkg>` | `rpm -q <pkg>` |
| 후보 버전 | `apt-cache policy <pkg>` | `dnf info <pkg>` | `pacman -Si <pkg>` | `zypper info <pkg>` |
| changelog | `apt-get changelog <pkg>` | `rpm -q --changelog <pkg>` | (`/var/log/pacman.log` 또는 패키지 PKGBUILD) | `rpm -q --changelog <pkg>` |
| 업그레이드 가능 목록 | `apt list --upgradable` | `dnf check-update` | `checkupdates` (pacman-contrib) | `zypper list-updates` |
| 보안 권고 목록 | `apt list --upgradable | grep -i security` | `dnf updateinfo list security` | `zypper list-patches --category security` |

## 자동 보안 업데이트

| 도구 | 활성화 |
|---|---|
| Debian/Ubuntu | `apt install -y unattended-upgrades && systemctl enable --now unattended-upgrades` |
| RHEL/Rocky | `dnf install -y dnf-automatic && systemctl enable --now dnf-automatic.timer` |
| Arch | (없음, 수동 권장) |
| SUSE | `zypper install -y yast2-online-update-configuration` 또는 cron |

## 커널 패키지 이름

| 배포판 | 메타패키지 / 실제 패키지 |
|---|---|
| Debian | `linux-image-amd64` → `linux-image-6.x.y-amd64` |
| Ubuntu | `linux-image-generic` → `linux-image-X.Y.Z-...-generic` |
| Proxmox VE | `proxmox-default-kernel` → `proxmox-kernel-6.X` → `proxmox-kernel-6.X.Y-Z-pve-signed` |
| RHEL/Rocky | `kernel` (직접) |
| Arch | `linux`, `linux-lts`, `linux-zen`, `linux-hardened` |
| SUSE | `kernel-default` |

커널 업그레이드 후 모든 배포판 공통: **재부팅이 필요**. `needs-restarting -r` (dnf) 또는 `needrestart -k` (apt)로 확인.

## 모듈 차단 위치

모든 배포판에서 동일:

```
/etc/modprobe.d/<name>.conf
```

문법:

```
install <module> /bin/false
# 또는
blacklist <module>
```

`blacklist`는 명시적 `modprobe`로는 여전히 로드된다. `install ... /bin/false`가 더 강하다.

## Mirror 변경 (속도 개선)

| 배포판 | 빠른 mirror로 바꾸는 법 |
|---|---|
| Ubuntu | `apt install -y mirrorselect && mirrorselect -t 6` 또는 GUI |
| Debian | `apt install -y netselect-apt && netselect-apt` |
| Arch | `reflector --country South\ Korea --age 12 --save /etc/pacman.d/mirrorlist` |
| Fedora | `dnf install -y dnf-plugin-fastest-mirror` 자동 |

## 설치 가능 후보 검증 (CVE 픽스 버전 들어왔는지)

```bash
# apt
apt-cache madison <pkg> | head -5

# dnf
dnf list available <pkg> --showduplicates | tail -10

# pacman
pacman -Si <pkg>
```

후보 버전이 CVE 권고의 픽스 컷오프 이상인지 직접 비교.

## 자주 쓰는 cross-distro 함수

`tools/lib/common.sh`의 `pkg_version()` / `detect_distro()` 참조. 스크립트 안에서:

```bash
. tools/lib/common.sh
detect_distro
case "$PKG_MGR" in
  apt)    apt update && apt install -y $PKG ;;
  dnf)    dnf install -y $PKG ;;
  pacman) pacman -Sy --noconfirm $PKG ;;
  zypper) zypper install -y $PKG ;;
esac
```
