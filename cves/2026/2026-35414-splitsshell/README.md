# CVE-2026-35414 — SplitSSHell (OpenSSH)

| | |
|---|---|
| 별명 | SplitSSHell |
| 컴포넌트 | OpenSSH (`authorized_keys` principals 처리) |
| 클래스 | 인증 우회 → root 로그인 |
| CVSS | 8.1 (High) |
| 공개 | 2026-04 |
| 픽스 | OpenSSH 10.3 이상 |

## 무엇이 문제인가

CA로 발급한 SSH 인증서의 principal 이름에 **콤마(`,`)** 가 들어가면 OpenSSH가 `authorized_keys`의 `principals=` 옵션을 잘못 파싱해 ACL을 우회한다. 신뢰하는 CA에서 발급한 유효 인증서만 있으면 root로 인증 가능.

## 영향 범위

- SSH 인증서(서명된 host key가 아니라 사용자 인증서) 기반 인증을 쓰는 환경
- `authorized_keys`에 `principals="alice,admin"` 같은 옵션을 거는 환경
- 일반 비밀번호/공개키 인증만 쓰는 환경은 영향 없음

## 진단

`sshd -V` (또는 `ssh -V`)로 OpenSSH 버전을 보고 10.3 미만이면 영향. 추가로 인증서 기반 인증 사용 여부도 봐야 한다 (`/etc/ssh/sshd_config`의 `TrustedUserCAKeys`).

## Mitigation

영구 패치 없이 즉시 노출을 줄이는 방법:

1. `TrustedUserCAKeys` 일시 제거 또는 인증서 인증 비활성화
2. `authorized_keys`의 `principals=` 옵션 제거 (모든 신뢰 CA 인증서를 일괄 허용하지 않도록)
3. `Match Principal` 블록으로 화이트리스트 강제

## 영구 패치

```bash
# Debian/Ubuntu
apt update && apt install -y openssh-server openssh-client

# RHEL/Rocky
dnf update -y openssh-server openssh-clients

# Arch
pacman -Syu openssh
```

업그레이드 후 `systemctl restart sshd`. 활성 세션은 영향 없음.

## 자료

- [SecurityWeek — SplitSSHell 분석](https://www.securityweek.com/openssh-flaw-allowing-full-root-shell-access-lurked-for-15-years/)
- [OpenSSH security advisories](https://www.openssh.org/security.html)
