# security-monitoring

Virtual Shelf 보안관제 전용 MSA

## Responsibilities

- security event monitoring
- log/metric/trace 기반 탐지
- detection rule execution
- security alert processing

## Monitored services

- backend-auth
- backend-record
- backend-book
- backend-discovery

## Architecture

```
MSA
 ↓
Logs / Metrics / Traces
 ↓
Loki / Prometheus / Tempo
 ↓
security-monitoring
 ↓
Detection
 ↓
Alert
```

## 현재 상태 (CLIAR-252)

실제 탐지/알림 연동 이전의 초기 골격입니다. 기존 MSA(backend-auth)의
공통 인프라/관측/배포 Convention만 이식했고, 아래는 아직 구현되지
않았습니다.

- Loki / Tempo / Prometheus 실제 조회 client
- Slack / email 등 알림 전송
- 실제 탐지 규칙(rule)
- 자체 DB(현재 이 서비스는 DB를 소유하지 않습니다)

## AWS OIDC / IAM 요구사항 (CLIAR-252)

`.github/workflows/build-push-ecr.yml`은 장기 AWS Access Key(GitHub
Secrets)를 저장하지 않고, GitHub Actions OIDC + IAM Role로 ECR에
인증합니다. 최소권한 원칙에 따라 **DEV/PROD Role을 분리**합니다 —
`Resolve target by branch` 스텝이 branch(develop/main)에 따라 Role
ARN을 함께 결정하고, 이후 `Configure AWS credentials` 스텝이 그 Role을
assume합니다. 아래는 AWS 쪽에서 준비해야 하는 값이며, **이 Git 작업
자체는 AWS 리소스를 생성하지 않습니다.**

### DEV

| 항목 | 값 |
| --- | --- |
| branch | `develop` |
| IAM Role | `gha-security-monitoring-ecr-dev` |
| Role ARN | `arn:aws:iam::594532711953:role/gha-security-monitoring-ecr-dev` |
| ECR | `dpyb-dev/dpyb-security-monitoring` |
| Trust 범위 | `dont-paw-get/security-monitoring` 저장소 + `develop` 브랜치로 제한 권장 |

### PROD

| 항목 | 값 |
| --- | --- |
| branch | `main` |
| IAM Role | `gha-security-monitoring-ecr-prod` |
| Role ARN | `arn:aws:iam::594532711953:role/gha-security-monitoring-ecr-prod` |
| ECR | `dpyb-prod/dpyb-security-monitoring` |
| Trust 범위 | `dont-paw-get/security-monitoring` 저장소 + `main` 브랜치로 제한 권장 |

### 공통

| 항목 | 값 |
| --- | --- |
| OIDC Provider | `token.actions.githubusercontent.com` (계정에 이미 등록되어 있어야 함) |
| Audience | `sts.amazonaws.com` |
| Region | `ap-northeast-2` |

**현재 실제 AWS 준비 범위는 DEV까지만입니다.** `gha-security-monitoring-ecr-dev`
Role과 `dpyb-dev/dpyb-security-monitoring` ECR만 생성 대상이며,
PROD(`gha-security-monitoring-ecr-prod`, `dpyb-prod/dpyb-security-monitoring`)는
아직 생성하지 않습니다 — Role/ECR이 없으므로 `main` push는
`AssumeRoleWithWebIdentity` 단계에서 실패합니다. DEV/PROD가 이제
서로 다른 Role을 쓰므로, DEV Role의 trust policy를 `develop` 브랜치로
제한해도 PROD 경로에 영향을 주지 않습니다(이전 단일 Role 구조에서
있었던 제약이 해소됨).

## 개발환경 준비

### 1. Python 가상환경 생성 및 활성화

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. 의존성 설치

```powershell
pip install -r requirements.txt
```

### 3. 환경변수 설정

`.env.example` 파일을 복사해 `.env` 파일을 생성하고 필요한 값을 채워주세요.

```powershell
Copy-Item .env.example .env
```

### 4. FastAPI 애플리케이션 실행

```powershell
uvicorn app.main:app --reload
```

### 5. GET /health 확인

```
GET http://127.0.0.1:8000/health
```
