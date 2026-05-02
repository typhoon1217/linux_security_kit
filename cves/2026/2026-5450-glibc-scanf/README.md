# CVE-2026-5450 — glibc scanf `%mc` Heap Buffer Overflow

| | |
|---|---|
| 컴포넌트 | GNU C Library (glibc) `scanf` 패밀리 |
| 클래스 | Heap buffer overflow → RCE / LPE |
| CVSS | **9.8 (Critical)** |
| 공개 | 2026-04 (Microsoft Patch Tuesday) |
| 포맷 specifier | `%mc` (allocate-and-store char) |

## 무엇이 문제인가

`scanf`/`sscanf`/`fscanf`가 `%mc` specifier를 처리할 때 **off-by-one heap buffer overflow**가 발생한다. 입력 길이 검증의 단일 바이트 누락으로 heap 메모리 인접 영역을 덮어쓸 수 있고, 공격자가 입력을 제어하면 임의 코드 실행까지 갈 수 있다.

## 영향 범위

- glibc를 동적 링크하는 **거의 모든 Linux 사용자공간 프로그램**
- 외부 입력을 `scanf` 계열로 받는 데몬·CLI 도구가 직접 노출 (예: 일부 네트워크 프로토콜 파서)
- 컨테이너 내부에서도 동일 영향 (호스트 glibc와 별개)

## 진단

glibc 버전과 배포판별 patch level을 확인. 픽스 컷오프는 배포판마다 다름:

| 배포판 | 픽스 버전 |
|---|---|
| Ubuntu 24.04 | `libc6 2.39-0ubuntu8.7+` |
| Debian Bookworm | `libc6 2.36-9+deb12u9+` |
| Debian Trixie | `libc6 2.41-12+deb13u3+` |
| RHEL 9 | `glibc-2.34-100+` (`rpm -q --changelog glibc | grep CVE-2026-5450`) |
| Arch | `glibc 2.41-2+` |

## Mitigation

런타임 mitigation 없음. **패치가 유일한 해결책**. 시간 벌기 위한 부분적 조치:

- 외부 입력을 `scanf %mc`로 받는 서비스 한정 비활성화
- 의심 서비스 앞에 입력 길이 제한 reverse proxy

## 영구 패치

```bash
# Debian/Ubuntu
apt update && apt install -y libc6 libc-bin

# RHEL/Rocky/Alma
dnf update -y glibc

# Arch
pacman -Syu glibc
```

업그레이드 후 **glibc를 동적 링크한 모든 서비스 재시작** 또는 호스트 재부팅. `apt`/`dnf`로 라이브러리 갱신만으론 메모리에 올라간 구버전이 그대로 동작.

## 자료

- [TechJack Solutions 분석](https://techjacksolutions.com/scc-intel/glibc-scanf-mc-off-by-one-heap-buffer-overflow-cve-2026-5450/)
- [GNU glibc CVE 목록](https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-767/GNU-Glibc.html)
