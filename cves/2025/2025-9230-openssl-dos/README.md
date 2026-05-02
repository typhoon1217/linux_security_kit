# CVE-2025-9230 / 9231 / 9232 — OpenSSL DoS

| | |
|---|---|
| 컴포넌트 | OpenSSL |
| 클래스 | Denial of Service (Important) |
| 공개 | 2025 (Q4 시리즈) |
| 픽스 컷오프 | 3.0.16 / 3.2.5 / 3.3.4 (배포판 백포트는 별개) |

## 무엇이 문제인가

OpenSSL이 특정 입력에 대해 비정상 종료하거나 무한 루프에 빠지는 DoS 결함 시리즈. 인증/암호화 파이프라인이 OpenSSL 위에 올라간 거의 모든 서비스(웹, 메일, VPN, 인증서 검증 등)에 영향. RCE/LPE는 아니지만 가용성 측면에서 실시간 노출.

## 진단

```bash
# 배포판별
dpkg -l | grep -E "^ii.*libssl|^ii.*openssl"   # apt
rpm -qa | grep -E "openssl"                    # dnf/yum
pacman -Q openssl                              # arch
```

3.0.16 / 3.2.5 / 3.3.4 미만이면 영향. 배포판이 `1.1.1*` 라인을 유지 중이라면 별도 backport 추적 필요.

## Mitigation

OpenSSL 자체에 mitigation은 없음. 노출을 줄이는 길은:

- 외부 노출 TLS 종단(웹서버, reverse proxy)에 rate limit 도입
- WAF/리버스 프록시에서 의심 트래픽 차단
- 미사용 TLS 종단 비활성화

## 영구 패치

배포판 표준 업그레이드:

```bash
# Debian/Ubuntu
apt update && apt install -y libssl3 openssl

# RHEL/Rocky
dnf update -y openssl openssl-libs

# Arch
pacman -Syu openssl
```

업그레이드 후 OpenSSL을 동적 링크하는 서비스들(Apache, Nginx, Postfix, OpenVPN 등)을 **재시작**해야 새 라이브러리 사용. 단순 `apt upgrade`만으로는 메모리 상의 구버전 라이브러리는 그대로 동작 — `needrestart`나 `dnf needs-restarting -r`로 검증.

## 자료

- [linuxsecurity.com — OpenSSL Flaws DoS Issues](https://linuxsecurity.com/news/security-vulnerabilities/openssl-flaws-linux-patch-coverage)
- [OpenSSL Vulnerabilities](https://www.openssl.org/news/vulnerabilities.html)
