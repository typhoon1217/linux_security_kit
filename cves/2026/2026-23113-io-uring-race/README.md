# CVE-2026-23113 — io_uring Race Condition (kernel panic / DoS)

| | |
|---|---|
| 컴포넌트 | Linux 커널 `io_uring` |
| 클래스 | Race condition → kernel panic |
| 영향 | DoS (multi-tenant 환경에서 더 위험), 잠재적 추가 익스플로잇 가능성 |
| 픽스 컷오프 | 6.12.3+ (mainline), 배포판별 백포트 |

## 무엇이 문제인가

io_uring worker thread 종료 시 exit flag 동기화가 부족해 정리 단계에서 자원 접근 race condition이 발생한다. 트리거 시 kernel panic으로 시스템 다운. cloud / 컨테이너 / 공유 호스팅처럼 unprivileged user가 shell 접근 있는 환경이면 다른 사용자 서비스를 마비시킬 수 있음.

## 영향 범위

- io_uring을 활성화한 모든 Linux 커널 (4.x 이후 광범위)
- multi-tenant Kubernetes 노드 / 공유 VPS / Proxmox LXC 노드 — **노출 위험 높음**
- 단일 사용자 데스크톱 — 영향 거의 없음 (자기 자신만 마비)

## 진단

`uname -r` 비교 + io_uring 활성 여부.

```bash
# io_uring 비활성화 여부
sysctl kernel.io_uring_disabled    # 0=완전허용, 1=일반사용자만, 2=전체차단
```

## Mitigation

io_uring을 비활성화하면 즉시 차단. 부작용: io_uring을 사용하는 일부 high-performance 애플리케이션 (Nginx 일부 빌드, MariaDB io_uring 엔진 등) 영향.

```bash
# 즉시 차단 (모든 사용자)
sysctl -w kernel.io_uring_disabled=2

# 영구화
echo 'kernel.io_uring_disabled=2' > /etc/sysctl.d/99-disable-io-uring.conf
```

## 영구 패치

배포판 커널을 6.12.3 이상 또는 백포트 적용된 버전으로 업그레이드. Proxmox는 `proxmox-kernel` 패키지 changelog에서 CVE-2026-23113 확인.

## 자료

- [Windows News — CVE-2026-23113 분석](https://windowsnews.ai/article/cve-2026-23113-how-a-small-io_uring-fix-prevents-major-linux-kernel-crashes.405964)
