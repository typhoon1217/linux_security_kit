# CVE-2026-35535 — sudo Privilege Drop Failure

| | |
|---|---|
| 컴포넌트 | sudo |
| 클래스 | privilege escalation (privilege drop call 실패) |
| 영향 | sudo가 일부 호출에서 권한을 제대로 떨어뜨리지 못해 root 권한 누출 가능 |
| 공개 | 2026 (Rocky Linux RLSA-2026-10758 등) |

## 무엇이 문제인가

sudo가 자식 프로세스에 권한을 위임할 때 일부 코드 경로에서 `setuid` 계열 system call이 실패해도 그것을 제대로 인지·중단하지 않는다. 결과적으로 본래 떨어뜨려야 할 root 권한이 일부 환경에서 남아있는 상태로 명령이 실행될 수 있다.

## 영향 범위

- sudo 1.9.x 라인의 특정 패치 이전 버전
- multi-tenant 시스템에서 이슈 더 큼

## 진단

```bash
sudo -V | head -1
dpkg-query -W -f '${Version}' sudo   # apt
rpm -q sudo                          # dnf
pacman -Q sudo                       # pacman
```

배포판 advisory에서 픽스 버전 확인:

| 배포판 | 픽스 버전 (예시) |
|---|---|
| Ubuntu 24.04 | `sudo 1.9.15p5-3ubuntu5.24.04.3+` |
| Debian Trixie | `sudo 1.9.16p2-1+deb13u1+` |
| RHEL 10 / Rocky 10 | `sudo-1.9.17-1.el10_0.1+` (RLSA-2026-10758) |
| Arch | 항상 최신 |

## Mitigation

런타임 mitigation은 sudo의 **사용을 줄이는 것** 정도. 부분적 조치:

- `sudoers`의 `NOPASSWD` 항목 임시 제거 (interaction 강제)
- `sudo` 대신 `doas` 또는 `pkexec` 사용 (가능한 경우)
- multi-tenant 환경에서 sudo 사용 사용자 격리

근본 해결은 패치.

## 영구 패치

```bash
# Debian/Ubuntu
apt update && apt install -y sudo

# RHEL/Rocky/Alma
dnf update -y sudo

# Arch
pacman -Syu sudo
```

업그레이드 즉시 적용. 활성 sudo 세션은 다음 호출부터 새 바이너리 사용.

## 자료

- [Rocky Linux RLSA-2026-10758](https://linuxsecurity.com/advisories/rockylinux/rocky-linux-rlsa-2026-10758-sudo-1777435873)
