# CVE-2026-0861 — glibc `memalign` Integer Overflow

| | |
|---|---|
| 컴포넌트 | GNU C Library (glibc) — `memalign`, `valloc`, `pvalloc`, `aligned_alloc` |
| 클래스 | Integer overflow → heap corruption → LPE/RCE |
| 영향 | Linux + WSL |
| 픽스 컷오프 | 배포판별 (CVE-2026-5450과 같은 시리즈에 묶여 패치되는 경우 많음) |

## 무엇이 문제인가

glibc의 정렬된 메모리 할당 함수 4개 (`memalign`, `valloc`, `pvalloc`, `aligned_alloc`)에서 **size 매개변수에 대한 정수 오버플로우**가 발생한다. 큰 size 값을 전달하면 내부 계산에서 wrap-around되어 작은 buffer를 할당한 뒤 호출자가 큰 buffer로 가정하고 사용 → heap corruption.

## 영향 범위

- glibc를 동적 링크하는 거의 모든 Linux 프로그램
- 메모리 할당기를 직접 사용하는 native 코드 (특히 high-performance 라이브러리)
- WSL에서도 동일

## 진단

CVE-2026-5450과 같은 시리즈로 묶여 패치되므로 **glibc 버전 체크가 동일**. `cves/2026/2026-5450-glibc-scanf/detect.sh`와 결과를 같이 본다.

추가 신호: 직접 `memalign`/`aligned_alloc`을 자주 호출하는 라이브러리(예: numpy, BLAS)를 쓰는 환경이 더 노출되기 쉬움.

## Mitigation

런타임 mitigation 없음. 패치가 유일.

## 영구 패치

`README.md` (CVE-2026-5450)과 동일.

## 자료

- [Windows News — CVE-2026-0861 분석](https://windowsnews.ai/article/cve-2026-0861-critical-glibc-memalign-vulnerability-threatens-linux-wsl-security.402505)
- [PurpleOps — glibc 핵심 취약점들](https://purple-ops.io/blog/glibc-critical-vulnerabilities)
