# CVE-2026-31431 — Copy Fail

| | |
|---|---|
| 별명 | Copy Fail |
| 컴포넌트 | Linux 커널 `algif_aead` (AF_ALG 인터페이스) |
| 클래스 | Local Privilege Escalation |
| CVSS | 7.8 (High) |
| 공개 | 2026-04-29 |
| Mainline 픽스 | 2026-04-01 (커밋 `a664bf3d603d`) |
| 패치 컷오프 | 6.18.22 / 6.19.12 / 7.0 |
| 도입 | Linux 4.14 (2017, 커밋 `72548b093ee3`) |

## 무엇이 문제인가

`algif_aead`가 2017년에 도입한 in-place 최적화가 source/destination scatterlist를 잘못 공유한다. AF_ALG 소켓을 `splice()`와 엮으면 **임의 readable 파일의 page cache에 4바이트 controlled write**가 가능하고, 이걸로 setuid root 바이너리를 변조해 root로 올라간다. PoC는 732바이트 Python 한 토막. Dirty Pipe보다 portability가 훨씬 높다.

## 영향 범위

- **모든 메인스트림 Linux 배포판의 4.14 이상 커널**.
- LXC 컨테이너는 호스트 커널을 공유하므로 호스트가 패치되지 않으면 컨테이너 안에서도 익스플로잇 성립. unprivileged 컨테이너의 user namespace 격리에도 불구하고 컨테이너 내 root까지는 올라감.

## 진단 (`detect.sh`)

세 가지를 본다:

1. **실행 커널이 패치 컷오프를 넘었는가** — 배포판별로 컷오프가 다름. `/etc/os-release`로 분기.
2. **`af_alg` / `algif_*` 모듈이 차단되어 있는가** — `/etc/modprobe.d/*` 안에서 `install ... /bin/false` 패턴 검색.
3. **autoload 시도 차단이 실제로 동작하는가** — `modprobe algif_aead` 호출 후 `lsmod`에 보이는지.

종료 코드: `0`=안전, `1`=취약, `2`=판단 불가.

## Mitigation (`mitigate.sh`)

재부팅 없는 응급 처치. `algif_*`와 `af_alg`의 `install` 라인을 `/bin/false`로 라우팅하고, 이미 로드된 모듈을 unload한다. 영향:

- ✅ 일반 사용자공간(웹, DB, 컨테이너 런타임)에는 영향 없음
- ⚠️ `cryptsetup` LUKS 키 derivation 일부 경로가 AF_ALG를 쓰는 환경에서는 영향 가능 — LUKS 사용 환경이라면 검증 필요
- ⚠️ `fscrypt` 사용 시도 영향 가능

Mitigation 적용 직후 `modprobe algif_aead`가 다음 메시지로 실패하면 정상:

```
modprobe: ERROR: Error running install command '/bin/false' for module af_alg: retcode 1
```

## 영구 패치

각 배포판에서 다음 버전 이상으로 커널 업그레이드:

| 배포판 | 픽스 버전 |
|---|---|
| Mainline | 6.18.22 / 6.19.12 / 7.0 |
| Debian Trixie | `linux 6.12.85-1` (DSA-6238-1) |
| Debian Bookworm | `linux 6.1.170-1` (DSA-6243-1) |
| Ubuntu | USN 별도 (Canonical 블로그 참조) |
| Proxmox VE | `proxmox-kernel-6.17 6.17.13-5` 이상, 또는 7.0 라인 |
| Arch Linux | `linux 6.19.12-1` 이상 |
| RHEL/Rocky/Alma | dnf의 kernel 패키지 changelog에서 CVE-2026-31431 확인 |

업그레이드 후 **재부팅 필수**. mitigation을 미리 걸어 두면 재부팅 일정을 여유 있게 잡을 수 있다.

## 관련 자료

- [oss-security 권고](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [theori-io PoC 리포지토리](https://github.com/theori-io/copy-fail-CVE-2026-31431)
- [Canonical 패치 안내](https://canonical.com/blog/copy-fail-vulnerability-fixes-available)
- [CERT-EU 권고 2026-005](https://cert.europa.eu/publications/security-advisories/2026-005/)
