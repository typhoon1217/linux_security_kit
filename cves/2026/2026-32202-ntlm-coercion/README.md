# CVE-2026-32202 — NTLM Authentication Coercion (zero-click)

| | |
|---|---|
| 컴포넌트 | SMB / NTLM 처리 (Linux 측은 Samba 클라이언트, Windows 호환 Stack) |
| 클래스 | zero-click 인증 강제 (NTLM relay) |
| 공개 | 2026-04 |
| 출처 | APT28 zero-day의 regression |

## 무엇이 문제인가

이전 패치에서 부분 픽스된 NTLM coercion 결함이 회귀했다. 사용자 상호작용 없이 NTLM 인증을 강제 트리거할 수 있어, 공격자가 hash relay나 NTLMv2 크래킹 단계를 진행할 수 있다.

## Linux 환경에서의 영향

Linux 단독 환경이면 영향 거의 없음. 다만:

- **Samba 클라이언트로 Windows 도메인에 마운트하는 환경**: 영향 가능
- **AD 통합 SSSD**: NTLM authentication이 활성화되어 있으면 검토 필요
- **`smbclient`, `mount.cifs` 사용 중**: 외부 SMB 서버에 연결할 때 trust 경계 재확인

## 진단

```bash
# Samba 패키지 버전
samba-tool --version 2>/dev/null
smbclient --version 2>/dev/null

# 활성 마운트 중인 SMB/CIFS
mount -t cifs
```

## Mitigation

- `mount.cifs`에 `vers=3.1.1`과 `seal` 옵션 강제 (NTLM downgrade 차단)
- 외부 SMB 서버로의 자동 마운트(`/etc/fstab`, `autofs`) 임시 비활성화
- AD 환경: NTLM 인증 비활성화 검토 (`smb.conf`에 `ntlm auth = no`)

## 영구 패치

배포판의 Samba/CIFS 패키지를 최신으로 업그레이드. Microsoft 측 패치 노트와 함께 추적 필요 — Linux 단독 패치만으로는 NTLM relay attack chain을 끊지 못할 수 있음.

## 자료

- 배포판 보안 트래커에서 CVE 번호로 검색해 정확한 패치 버전 확인 권장.
