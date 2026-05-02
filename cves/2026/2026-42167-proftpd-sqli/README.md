# CVE-2026-42167 — ProFTPD `mod_sql` SQL Injection → RCE

| | |
|---|---|
| 컴포넌트 | ProFTPD `mod_sql` (DB 기반 인증/저장) |
| 클래스 | SQL injection → RCE / 인증 우회 / 권한 상승 |
| 공개 | 2026 (ZeroPath Research) |
| 픽스 | ProFTPD 다음 패치 릴리스 (배포판 advisory 추적) |

## 무엇이 문제인가

`mod_sql`이 사용자 입력에서 SQL escape를 누락해, 인증 단계에서 임의 쿼리 실행을 허용한다. 일부 설정에서 **pre-auth RCE**, 다른 설정에서 인증 우회 + privilege escalation까지 가능. 데이터베이스 백엔드 + 적절한 SQL functions 조합이면 OS command 실행 chain까지 이어짐.

## 영향 범위

- ProFTPD를 운영 중이면서 `mod_sql`을 활성화한 환경 (DB 기반 사용자 인증)
- 외부 인터넷에 21번 포트 노출된 호스트면 unauthenticated 공격 가능

## 진단

```bash
proftpd -v
dpkg-query -W -f '${Version}' proftpd-basic    # apt
rpm -q proftpd                                  # dnf

# mod_sql 활성?
proftpd -l 2>/dev/null | grep mod_sql
grep -hE "^[[:space:]]*Include|^[[:space:]]*LoadModule.*mod_sql" /etc/proftpd/proftpd.conf /etc/proftpd/conf.d/*.conf 2>/dev/null
```

mod_sql 빌드 + 활성 = 노출.

## Mitigation

### 옵션 1 — `mod_sql` 비활성

DB 기반 인증을 일시 중단할 수 있으면 가장 안전:

```bash
# proftpd.conf 또는 modules.conf에서 mod_sql LoadModule 라인 주석
# 또는
systemctl stop proftpd
```

### 옵션 2 — 외부 노출 차단

```bash
# 21번 포트를 신뢰 IP만 허용
nft add rule inet filter input tcp dport 21 ip saddr != { 10.0.0.0/8 } drop
```

### 옵션 3 — WAF 또는 SFTP로 대체

신규 연결을 SFTP(SSH 22번)로 옮기고 ProFTPD 데몬 정지. 운영 영향 큼.

## 영구 패치

```bash
# Debian/Ubuntu
apt update && apt install -y proftpd-basic proftpd-mod-mysql proftpd-mod-pgsql

# RHEL/Rocky
dnf update -y proftpd

# Arch
pacman -Syu proftpd
```

업그레이드 후 `systemctl restart proftpd`. 패치 버전은 배포판 advisory에서 확인.

## 자료

- [ZeroPath Blog — CVE-2026-42167 분석](https://zeropath.com/blog/proftpd-cve-2026-42167-auth-bypass-privesc-rce)
