# CVE-2024-1086 — Flipping Pages (잔류 위험)

| | |
|---|---|
| 별명 | Flipping Pages |
| 컴포넌트 | Linux 커널 `nf_tables` (netfilter) |
| 클래스 | Use-after-free → LPE |
| CVSS | 7.8 (High) |
| 공개 | 2024-01-31 |
| 픽스 컷오프 | 5.15.149 / 6.1.76 / 6.6.15 / 6.7.3 (배포판 백포트는 별개) |
| KEV | CISA Known Exploited Vulnerabilities 등재 |

## 왜 2026년에도 다루나

2024년에 패치되었지만 **CISA KEV 목록 등재**, 그리고 RansomHub·Akira 같은 ransomware operator가 post-compromise privilege escalation에 이 익스플로잇을 적극 사용 중. 패치 사이클이 늦은 운영 환경에 여전히 남아있을 가능성이 높아 잔류 위험으로 취급.

## 무엇이 문제인가

`nf_tables`의 verdict 처리 경로에서 use-after-free가 발생. 커널 객체 주소를 dangling reference로 만들고 재할당해 임의 메모리 조작 → privilege escalation. unprivileged user namespace 안에서도 트리거 가능 (그게 핵심).

## 진단

배포판 커널의 changelog에서 CVE-2024-1086 명시 확인이 가장 확실. 보조적으로:

- `unshare -rUm true` 가능 여부 (unprivileged user namespace 활성)
- 커널 빌드 일자가 2024-02 이후인지

## Mitigation

근본은 user namespace를 제한하는 것:

```bash
# unprivileged user namespace 비활성화
sysctl -w kernel.unprivileged_userns_clone=0

# 영구화
echo 'kernel.unprivileged_userns_clone=0' > /etc/sysctl.d/99-disable-userns.conf
```

부작용: Docker rootless, Chrome sandbox, snap, Flatpak 일부 기능이 망가질 수 있음. 사용 환경 점검 필수.

## 영구 패치

배포판 표준 커널 업그레이드. 위 컷오프 이상의 버전에 백포트 적용 여부는 배포판 보안 트래커에서 확인.

## 자료

- [Linux Journal — 가장 critical한 2025 커널 이슈](https://www.linuxjournal.com/content/most-critical-linux-kernel-breaches-2025-so-far)
- [LinuxSecurity — KEV에 오른 커널 이슈들](https://linuxsecurity.com/news/security-vulnerabilities/7-linux-kernel-vulnerabilities-exploited-in-2025)
