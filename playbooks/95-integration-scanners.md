# 95 — 오픈소스 통합 검증 스캐너

이 키트의 detect.sh가 "선정된 CVE 목록"을 직접 점검하는 방식이라면, 통합 스캐너는 **광범위 데이터베이스 매칭**으로 미등록 CVE까지 잡아낸다. 둘은 보완적 — 키트는 결정·mitigation까지 적용하는 운영 도구, 스캐너는 누락 점검의 안전망.

## 추천 스택

| 도구 | 강점 | 약점 | 키트와의 관계 |
|---|---|---|---|
| **Trivy** (Aqua) | 컨테이너·파일시스템·repo·IaC·SBOM 한 바이너리. CVE/오인 적음. | RCE 시나리오 분석은 안 함 (데이터베이스 매칭 위주) | 키트가 호스트·LXC 진단, Trivy가 OS 패키지 + 컨테이너 이미지 |
| **Grype** (Anchore) | SBOM 기반, false positive 매우 낮음 | 컨테이너/파일시스템만 (config 정책 안 함) | Trivy 보완용 |
| **Lynis** | Linux/UNIX 호스트 보안 감사 (auditing 위주) | CVE 매칭 약함 | 키트의 `tools/check-host.sh`와 보완 — Lynis는 정책, 키트는 CVE |
| **Vuls** | 멀티 호스트 원격 스캔, agent-less, 한국어 보고 가능 | 셋업 복잡, NVD/OVAL 의존 | 다수 호스트 한 번에 스캔할 때 |
| **OpenSCAP** | NIST SCAP 표준, 정부·금융 규정 준수 | 무거움, 정책 오버헤드 | 컴플라이언스 강제 환경 |
| **OSV-Scanner** (Google) | OSV 데이터베이스 기반, 언어 라이브러리 강함 | OS 패키지 약함 | 애플리케이션 dependency용 |

## 빠른 적용 — Trivy

호스트 + 컨테이너 모두 한 번에:

```bash
# 설치 (Debian/Ubuntu)
sudo apt install -y trivy
# 또는 정적 binary
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin

# 호스트의 모든 OS 패키지 스캔
sudo trivy rootfs --scanners vuln,misconfig /

# Proxmox 위 LXC 컨테이너 rootfs 직접 스캔 (호스트에서)
for ct in $(pct list | awk 'NR>1 {print $1}'); do
  rootfs=/var/lib/lxc/$ct/rootfs   # PVE 9 기준 (lxc 라인이 다른 경우 pct config $ct 확인)
  echo "=== CT $ct ==="
  sudo trivy rootfs --severity CRITICAL,HIGH "$rootfs"
done

# Docker 이미지
trivy image nginx:latest

# IaC + secrets
trivy fs --scanners secret,misconfig /path/to/repo
```

추천 옵션:

```bash
trivy --severity CRITICAL,HIGH --exit-code 1 ...   # 자동화에서 빌드 실패 트리거
trivy --skip-files /var/log,/proc,/sys ...         # 노이즈 제거
trivy --offline-scan --db-repository registry.cn-hangzhou.aliyuncs.com/aquasecurity/trivy-db
                                                    # 폐쇄망 미러
```

## Lynis 한 줄

```bash
sudo lynis audit system
```

리포트는 `/var/log/lynis-report.dat`. 키트의 `check-host.sh`가 CVE 노출에 집중한다면, Lynis는 SSH 설정·sysctl·파일 권한 같은 hardening 항목을 잡는다.

## Vuls (다수 호스트 원격 스캔)

```bash
# 마스터 호스트에 vuls 설치 후
vuls config init
vuls scan -config=config.toml         # 등록한 모든 호스트 SSH로 스캔
vuls report -format-json
```

NVD/OVAL DB를 미리 받아두는 게 정석 (`go-cve-dictionary`, `goval-dictionary`).

## 이 키트와 연결하는 패턴

`tools/scan-all-cves.sh`를 먼저 돌려 **선정된 CVE에 대한 결정적 verdict**(취약/안전/mitigation 적용됨)를 얻고, 이어서 Trivy로 **광범위 매칭**을 돌려 누락된 CVE를 찾는다. 두 결과를 합치면:

- 키트 → "이 CVE에 대해 호스트는 안전, 컨테이너 X는 mitigation 필요"
- Trivy → "키트에 등록 안 된 다른 CVE 12개 존재"

후자에서 운영상 의미 있는 항목을 추려 키트의 `cves/<id>/`에 새 디렉토리로 등록하는 식으로 키트가 점진적으로 진화한다.

## CI/CD 통합 예시

GitHub Actions:

```yaml
- uses: aquasecurity/trivy-action@master
  with:
    scan-type: fs
    severity: CRITICAL,HIGH
    exit-code: '1'
    format: sarif
    output: trivy.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: trivy.sarif
```

GitLab CI:

```yaml
trivy_scan:
  image: aquasec/trivy:latest
  script:
    - trivy fs --severity CRITICAL,HIGH --exit-code 1 .
```

## 대형 enterprise 옵션 (참고)

- **GitHub Advanced Security (GHAS)**: 코드 + dependency + secret. GitHub 조직 종속, 유료.
- **Snyk**: SaaS, 라이브러리 dependency 강함, 무료 tier 있음.
- **Tenable Nessus**: 호스트·네트워크 통합, 라이선스.

본 키트는 OSS만으로 운영 가능한 수준을 목표로 함. 위 SaaS는 보조 안전망으로 고려.

## 결론

**키트 + Trivy 조합**이 가장 현실적. 키트는 결정과 mitigation까지 가는 도구고, Trivy는 광범위 안전망. 둘 다 매주 자동 실행 + 결과 diff로 알림하는 게 표준 구성.
