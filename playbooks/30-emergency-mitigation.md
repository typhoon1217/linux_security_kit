# 30 — 응급 Mitigation 모음

재부팅 없이, 패치 없이, 분 단위 안에 공격 표면을 닫는 기법들. 영구 해결책이 아니라 **시간을 버는 도구**.

## 일반 원칙

1. **차단이 안전 (fail closed)**. 의심스러운 인터페이스는 일단 막고, 영향이 확인되면 일부 풀어준다.
2. **명시적 백업**. 수정한 설정 파일은 `*.cve-XXXX-XXXX.bak`으로 백업 — 영구 패치 후 원상 복구할 때 추적 가능.
3. **mitigation 적용 후에도 패치 일정은 잡는다.** Mitigation은 deadline이 있는 빌린 시간.

## 커널 모듈 차단 (load 자체 막기)

```bash
# 패턴: 모듈이 자동 로드되는 걸 install 라인으로 차단
cat > /etc/modprobe.d/disable-<module>-cve.conf <<EOF
install <module> /bin/false
EOF

# 이미 로드되어 있으면 unload
modprobe -r <module>
```

검증: `modprobe <module>`이 다음 메시지로 실패해야 정상.

```
modprobe: ERROR: Error running install command '/bin/false' for module <module>: retcode 1
```

대표 적용:
- CVE-2026-31431 (Copy Fail): `algif_aead`, `algif_skcipher`, `algif_hash`, `algif_rng`, `af_alg`
- 과거 Dirty Pipe류: 별도 mitigation 없음, 패치 필수

## 시스템 호출 비활성화

```bash
# user namespace 차단 (CVE-2024-1086 등)
sysctl -w kernel.unprivileged_userns_clone=0
echo 'kernel.unprivileged_userns_clone=0' > /etc/sysctl.d/99-disable-userns.conf
```

부작용: rootless Docker, Chrome sandbox, snap, Flatpak 일부 기능 영향. 환경 점검 후 적용.

## 서비스 임시 비활성화

```bash
systemctl stop <service>
systemctl disable <service>
```

영향력 낮은 서비스 (예: 외부 노출 미사용 인터페이스)라면 가장 깔끔한 선택. 재기동만 하면 mitigation 해제도 즉시.

## 네트워크 단에서 닫기

```bash
# nftables 빠른 차단
nft add rule inet filter input tcp dport <port> drop

# iptables 호환
iptables -I INPUT -p tcp --dport <port> -j DROP

# Proxmox에서 컨테이너별 firewall 활성
pct set <vmid> -net0 ...,firewall=1
```

WAF/리버스 프록시 단에서 막을 수 있으면 그게 가장 효과적 (호스트 부하 없음).

## SSH 인증 경로 닫기

```bash
# CVE-2026-35414 (SplitSSHell) 류: TrustedUserCAKeys 잠시 비활성
sed -i.bak 's|^\(TrustedUserCAKeys\)|# CVE-disabled: \1|' /etc/ssh/sshd_config
sshd -t && systemctl reload sshd
```

원복은 백업 파일 복사로 1줄.

## 파일 시스템 권한 강화

```bash
# setuid 바이너리 일시 비활성 (특정 바이너리 한정 권장)
chmod u-s /usr/bin/<binary>

# 영구 패치 적용 후 원복
chmod u+s /usr/bin/<binary>
```

setuid 전부 한 번에 죽이면 sudo, ping 등 정상 동작도 깨지니 표적 한정.

## Mitigation 적용 후 반드시 할 일

1. **변경 사항 기록** — `cve-mitigation-log.md` 같은 운영 노트에 무엇을, 언제, 왜 적용했는지.
2. **Deadline 설정** — 영구 패치 일정을 캘린더에 박는다. Mitigation은 영원히 둘 게 아니다.
3. **`tools/scan-all-cves.sh`로 재검증** — mitigation이 실제로 작동하는지 확인.

## 검증 체크리스트

- [ ] 적용 직후: 공격 벡터가 실제로 차단됐는지 PoC 또는 attempt log로 확인
- [ ] 24시간 후: 운영 시스템에 부작용 없는지 (오류 로그, 사용자 보고)
- [ ] 영구 패치 후: mitigation 원복 (필요 시)
- [ ] 운영 노트에 사이클 끝났음을 기록
