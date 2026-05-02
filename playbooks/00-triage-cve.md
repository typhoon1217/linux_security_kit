# 00 — 새 CVE 트리아지

CVE 권고가 떴을 때 운영 환경 영향을 30분 안에 판정하기 위한 흐름. 결과는 "패치 즉시", "응급 mitigation 후 일정 잡기", "영향 없음" 셋 중 하나.

## 1단계 — 권고 정독 (5분)

답을 찾아야 할 질문:

- 컴포넌트는 무엇인가? (커널 / openssh / openssl / Samba / 특정 라이브러리)
- 클래스는? (LPE / RCE / DoS / 정보 유출)
- pre-auth인가 post-auth인가? unauth 외부 접근으로 트리거되면 우선순위 최상.
- 픽스 컷오프 버전은?
- mainline 픽스 일자는? — 빌드 일자가 그 이전이면 거의 확실히 영향.
- PoC 공개됐나? PoC 있으면 mitigation 우선 적용.

## 2단계 — 노출 표 작성 (5분)

| 호스트/컨테이너 | 버전 | 컴포넌트 사용? | 노출 경로 | 확정 |
|---|---|---|---|---|
| (예) prod-host | 6.17.2 | yes | unauth network | 영향 |
| (예) ct-foo | n/a | no | n/a | 영향 없음 |

LXC가 있는 환경에선 호스트 한 줄이 곧 컨테이너 전부의 줄이라는 점을 잊지 말 것 (커널 CVE의 경우).

## 3단계 — 진단 자동화 (10분)

이미 `cves/<id>/detect.sh`가 있으면 그걸 사용. 없으면 다음 셋을 본다:

```bash
# (a) 버전 비교
uname -r        # kernel
ssh -V          # openssh
openssl version # openssl

# (b) 동작 확인 — 컴포넌트가 실제로 활성화되어 있는가
lsmod | grep <module>
systemctl is-active <service>

# (c) 공격 표면 — 인터넷에 노출됐는가
ss -tlnp | grep :<port>
```

## 4단계 — 결정 트리

```
영향 없음 ──────────────────────────────► 종료, 다음 권고로
영향 있음 ─┬─ pre-auth & PoC 공개 ──────► 응급 mitigation 즉시
           │                              + 같은 날 안에 영구 패치
           ├─ post-auth 또는 PoC 없음 ──► 응급 mitigation 권장
           │                              + 다음 유지보수 창에 패치
           └─ 패치만 있고 mitigation 무 ► 패치 우선순위만 결정
```

## 5단계 — 응급 Mitigation

`playbooks/30-emergency-mitigation.md` 참조. 핵심: **재부팅 없는 처치를 먼저 적용해서 시간을 벌고**, 영구 패치는 일정에 맞춰 진행.

## 6단계 — 영구 패치

- 호스트 커널 패치: `playbooks/10-proxmox-host-patch.md` (Proxmox) 또는 일반 `apt full-upgrade && reboot`.
- LXC 컨테이너 userspace 패치: `playbooks/20-lxc-userspace-patch.md`.
- 패치 후 반드시 `tools/scan-all-cves.sh`로 재검증.

## 7단계 — 자료화

- 새 CVE는 `cves/<year>/<id>-<slug>/`에 README + detect + mitigate 추가
- `tools/scan-all-cves.sh`의 CVE 목록에 새 detect.sh 경로 추가
- `README.md`의 인덱스 표에 한 줄 추가

다음 환경에서는 이 키트를 통째로 가져가면 같은 절차가 30분이면 끝난다.
