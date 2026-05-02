# CVE-2026-31418 — netfilter conntrack helper 처리 결함

| | |
|---|---|
| 컴포넌트 | Linux 커널 netfilter (`nf_conntrack`, `ipset`) |
| 클래스 | network-triggered crash / memory corruption / 정책 우회 |
| 영향 | kernel panic, 보안 정책 우회 |
| 공개 | 2026 |

## 무엇이 문제인가

`nf_conntrack`의 expectation 생성 경로에서 helper lookup이 잘못된 매개변수로 호출되면 helper 미스 또는 잘못된 helper 매칭이 발생한다. 공격자가 패킷을 조작하면 kernel crash, 메모리 손상, 또는 netfilter 보안 정책 우회까지 가능.

## 영향 범위

- netfilter helper(connection tracking helper)를 활성화한 시스템 (FTP, TFTP, SIP, IRC, H.323 등)
- 라우터, 방화벽, NAT 노드 — 노출 위험 높음
- helper를 끄고 운영하는 서버는 영향 거의 없음

## 진단

```bash
# 활성 conntrack helpers
cat /proc/net/nf_conntrack_helper 2>/dev/null
modprobe -c | grep nf_conntrack_helper

# helper modules loaded
lsmod | grep ^nf_conntrack
```

## Mitigation

helper를 끄거나, 명시적으로 화이트리스트 한 helper만 허용. 자동 helper assignment를 끄는 것이 가장 안전:

```bash
# 자동 helper assignment 비활성화
sysctl -w net.netfilter.nf_conntrack_helper=0
echo 'net.netfilter.nf_conntrack_helper=0' > /etc/sysctl.d/99-conntrack-helper.conf
```

부작용: FTP active mode 등 helper에 의존하는 프로토콜이 깨질 수 있음. 필요하면 nftables 규칙으로 명시 helper 등록 (`ct helper "ftp"`).

## 영구 패치

배포판 커널 업그레이드. Proxmox는 `proxmox-kernel` 패키지 changelog 확인.

## 자료

- [Windows News — CVE-2026-31418 분석](https://windowsnews.ai/article/linux-kernel-security-patch-cve-2026-31414-fixes-netfilter-conntrack-vulnerability.412495)
