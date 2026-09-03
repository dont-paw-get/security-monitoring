# security-monitoring

Virtual Shelf AWS 계정의 GuardDuty 보안 위협 탐지를 Bedrock으로 분석하고,
검증된 분석 결과를 Discord(Primary) 또는 SNS 이메일(Fallback)로
관리자에게 알리는 보안관제 MSA입니다.

## 프로젝트 목적

AWS GuardDuty가 계정 전체에서 탐지한 보안 위협(Finding)을 사람이 바로
읽을 수 있는 한국어 분석(원인/영향/권장 대응)으로 변환해 관리자에게
전달합니다. 이 서비스는 탐지(GuardDuty)나 알림 채널(Discord/SNS)을
직접 만들지 않고, 그 사이에서 **Finding 정규화 → AI 분석 →
검증 → 알림 발행(Discord 우선, 실패 시 SNS)**을 오케스트레이션합니다.

## 전체 아키텍처

```
GuardDuty (AWS 위협 탐지)
  │ EventBridge 규칙: severity >= 4 인 Finding만 전달
  ▼
EventBridge
  ▼
SQS (dpyb-security-monitoring-guardduty-dev)
  │                                    실패(아래 "실패/재시도/DLQ" 참고)
  │                                            │
  ▼                                            ▼
security-monitoring (이 서비스)                DLQ (dpyb-security-monitoring-guardduty-dlq-dev)
  │ GuardDuty Finding 파싱/정규화
  ▼
Amazon Bedrock (Claude Haiku 4.5, Converse API)
  │ summary / cause / impact / recommended_actions 생성
  │ (risk_level은 LLM이 아니라 severity로 코드에서 결정적으로 계산)
  ▼
AI 응답 검증 (JSON decode → Pydantic 스키마 검증)
  ▼
Discord Webhook (Primary, DISCORD_WEBHOOK_URL 설정된 경우만)
  │ 성공 → SNS는 호출하지 않음(중복 알림 방지) ──────────┐
  │ 실패 또는 미설정                                       │
  ▼                                                        │
Amazon SNS (dpyb-security-monitoring-alerts-dev, Fallback) │
  │ 관리자 이메일 구독                                      │
  ▼                                                        ▼
SQS DeleteMessage (Discord 또는 SNS 중 하나라도 성공했을 때만)
```

## 각 서비스 역할

| 서비스 | 역할 |
| --- | --- |
| GuardDuty | AWS 계정의 위협을 자동 탐지해 Finding을 생성 |
| EventBridge | severity ≥ 4인 Finding만 골라 SQS로 전달 |
| SQS | security-monitoring이 안정적으로 처리할 수 있도록 Finding을 버퍼링 |
| DLQ | 반복 실패한 메시지를 격리(최대 5회 재시도 후 자동 이동) |
| Bedrock | 위험 원인/영향/대응 권고를 한국어로 분석 (자동 대응 없음) |
| Discord (AWS 서비스 아님) | 검증된 분석 결과를 관리자 채널에 우선 발행(Primary). 미설정/실패 시 SNS로 대체 |
| SNS | Discord가 없거나 실패했을 때 관리자 이메일로 발행(Fallback) |
| IRSA | Pod가 Static AWS Credential 없이 SQS/Bedrock/SNS API를 사용하도록 인증 |

## security-monitoring의 역할

이 서비스 자체는 탐지 규칙도, 알림 채널도 소유하지 않습니다. FastAPI
애플리케이션 안에서 백그라운드 워커(`MonitoringWorker`,
`app/services/monitoring_worker.py`)가 SQS를 long polling으로 소비하며,
Finding 하나마다 아래 "처리 순서"를 순서대로 실행합니다.

## 처리 순서

`app/services/monitoring_worker.py`의 `MonitoringWorker._handle_body`가
메시지 1건에 대해 실행하는 순서입니다. **각 단계 중 하나라도 실패하면
이후 단계는 실행하지 않고, SQS 메시지도 삭제하지 않습니다.**

1. SQS 메시지 Body(JSON 문자열) 파싱
2. GuardDuty EventBridge 이벤트 → `GuardDutyFinding` 정규화
   (`app/services/guardduty_parser.py`)
3. Bedrock Converse 호출로 AI 분석 (`app/services/security_analysis.py`,
   `app/providers/bedrock.py`)
4. AI 응답 JSON 디코드 + Pydantic 스키마 검증, `risk_level`은 severity
   기반으로 코드에서 재계산
5. `DISCORD_WEBHOOK_URL`이 설정되어 있으면 Discord Webhook 발행 시도
   (`app/services/alert_message.py`의 `build_discord_payload`,
   `app/providers/discord.py`)
   - 성공하면 SNS는 호출하지 않습니다(중복 알림 방지).
   - 실패하거나 애초에 설정되어 있지 않으면 6번으로 진행합니다.
6. SNS Publish로 관리자 이메일 알림(Fallback) —
   `build_alert` + `app/providers/sns.py`
7. 위(5 또는 6) 중 하나라도 성공한 경우에만 SQS `DeleteMessage`

boto3 호출(SQS/Bedrock/SNS)과 Discord Webhook HTTP 호출은 모두
동기(synchronous)이므로, `asyncio.to_thread`로 감싸 FastAPI/asyncio
이벤트 루프를 막지 않습니다.

## 프로젝트 디렉터리 구조

```
app/
├── api/            # HTTP 라우터
│   ├── health.py       # GET /health
│   └── metrics.py      # GET /metrics (Prometheus)
├── core/
│   ├── config.py        # 환경변수 (pydantic-settings)
│   ├── logging_config.py  # stdout JSON 구조화 로깅
│   ├── metrics.py         # Prometheus HTTP 메트릭 미들웨어
│   └── observability.py   # OpenTelemetry 분산 추적 설정
├── providers/       # 외부 API client 래퍼 — 각 client 생성 + 단일 API 호출만 담당
│   ├── bedrock.py       # boto3 bedrock-runtime, Converse
│   ├── discord.py        # httpx, Discord Incoming Webhook POST
│   ├── sns.py             # boto3 sns.publish
│   └── sqs.py              # boto3 receive_message / delete_message
├── schemas/         # Pydantic 모델
│   ├── guardduty.py            # GuardDutyFinding
│   └── security_analysis.py    # AIAnalysisContent / SecurityAnalysis / RiskLevel
├── services/        # 비즈니스 로직 오케스트레이션
│   ├── alert_message.py     # SecurityAnalysis + GuardDutyFinding -> SNS 텍스트 / Discord embed
│   ├── guardduty_parser.py  # EventBridge 이벤트 -> GuardDutyFinding
│   ├── monitoring_worker.py # SQS Consumer lifecycle + 전체 처리 순서(Discord Primary/SNS Fallback 포함)
│   └── security_analysis.py # Bedrock 프롬프트 구성 + 응답 검증 + risk_level 계산
└── main.py           # FastAPI app, lifespan에서 monitoring_worker 시작/종료

tests/                # pytest 단위 테스트 — 실제 AWS/Discord를 호출하지 않고 mock/monkeypatch만 사용
k8s/                  # Kustomize base + overlays(dev, prod)
argocd/               # ArgoCD Application 매니페스트(dev, prod)
.github/workflows/    # CI — ECR 빌드/푸시, PR 컨벤션 체크
```

## 환경변수

`.env.example`을 복사해 `.env`로 사용합니다. 비밀값은 없습니다 — 모든
AWS 인증은 IRSA(Static Credential 없음)로 이뤄집니다.

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `APP_ENV` | `development` | 환경 이름(로그/트레이스 구분용) |
| `APP_HOST` | `0.0.0.0` | uvicorn bind host |
| `APP_PORT` | `8000` | uvicorn bind port |
| `LOG_LEVEL` | `INFO` | 로그 레벨 |
| `LOG_FORMAT` | `json` | `json`(운영/수집용) 또는 `text`(로컬 개발용) |
| `MONITORING_ENABLED` | `false` | `true`일 때만 SQS 소비 워커가 시작됨 |
| `AWS_REGION` | `ap-northeast-2` | SQS/SNS 호출 리전 |
| `SQS_GUARDDUTY_QUEUE_URL` | (없음) | GuardDuty Finding이 도착하는 SQS 큐 URL |
| `BEDROCK_REGION` | `ap-northeast-2` | Bedrock Runtime 호출 리전 |
| `BEDROCK_MODEL_ID` | `global.anthropic.claude-haiku-4-5-20251001-v1:0` | Bedrock Converse에 쓸 모델/Inference Profile ID |
| `SNS_ALERT_TOPIC_ARN` | (없음) | 관리자 알림을 발행할 SNS Topic ARN(Fallback 채널, 필수) |
| `DISCORD_WEBHOOK_URL` | (없음) | 관리자 알림을 우선 발행할 Discord Incoming Webhook URL(Primary 채널, 선택) |

`MONITORING_ENABLED=true`인데 `SQS_GUARDDUTY_QUEUE_URL` 또는
`SNS_ALERT_TOPIC_ARN`이 비어 있으면, 워커는 에러 로그만 남기고 polling을
시작하지 않습니다(애플리케이션 자체는 정상 기동). `DISCORD_WEBHOOK_URL`은
필수가 아닙니다 — 비어 있으면 worker는 정상 시작하고 모든 알림을 SNS로만
보냅니다. `DISCORD_WEBHOOK_URL`은 Secret이므로 `.env`/K8s ConfigMap 등
평문 설정 파일에 실제 값을 커밋하지 않습니다 — 준비되면 K8s Secret으로
주입합니다(아직 이 저장소에 Secret 매니페스트는 없습니다).

`OTEL_SERVICE_NAME` / `OTEL_EXPORTER_OTLP_ENDPOINT` /
`OTEL_RESOURCE_ATTRIBUTES` 등 OpenTelemetry 표준 환경변수는
`app/core/observability.py`가 SDK를 통해 직접 읽으며, 위 `Settings`
클래스에는 포함되지 않습니다.

## 로컬 실행

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

```powershell
Copy-Item .env.example .env
```

로컬에서는 `MONITORING_ENABLED=false`(기본값)로 두면 AWS 호출 없이
`/health`, `/metrics`만으로 애플리케이션을 확인할 수 있습니다. 실제로
SQS/Bedrock/SNS를 호출하려면 위 환경변수를 채우고 로컬 AWS 자격증명이
필요합니다.

### 4. FastAPI 애플리케이션 실행

```powershell
uvicorn app.main:app --reload
```

### 5. 확인

```
GET http://127.0.0.1:8000/health
GET http://127.0.0.1:8000/metrics
```

## 테스트

실제 AWS/Discord를 호출하지 않습니다 — `app/providers/*`의 boto3/httpx
호출 지점을 `monkeypatch`로 대체합니다.

```powershell
pytest -q
python -m compileall app
```

주요 테스트 파일:

- `tests/test_guardduty_parser.py` — EventBridge 이벤트 파싱
- `tests/test_sqs_provider.py`, `tests/test_monitoring_worker.py` — SQS 소비/재시도/DLQ, Discord Primary/SNS Fallback 전체 처리 순서
- `tests/test_bedrock_provider.py`, `tests/test_security_analysis.py` — Bedrock 호출, 프롬프트, 응답 검증, `risk_level` 계산
- `tests/test_sns_provider.py`, `tests/test_discord_provider.py`, `tests/test_alert_message.py` — SNS Publish, Discord Webhook Publish, 알림 텍스트/embed 구성
- `tests/test_health.py`, `tests/test_metrics.py` — 기본 HTTP 엔드포인트

## DEV 배포

`develop` 브랜치에 push되면 GitHub Actions(`.github/workflows/build-push-ecr.yml`)가
OIDC로 `gha-security-monitoring-ecr-dev` Role을 assume해 ECR
(`dpyb-dev/dpyb-security-monitoring`)에 이미지를 푸시하고,
`k8s/overlays/dev/kustomization.yaml`의 `newTag`를 커밋 SHA로 갱신하는
커밋을 같은 브랜치에 남깁니다. ArgoCD(`argocd/application-dev.yaml`)가
`develop` 브랜치의 `k8s/overlays/dev`를 자동 동기화합니다
(namespace: `dpyb-security-monitoring-dev`).

Runtime Pod는 `security-monitoring` ServiceAccount를 통해 IRSA Role
`dpyb-security-monitoring-irsa-dev`를 사용합니다. 이 Role은 목적별로
최소권한만 갖습니다.

- SQS: 위 GuardDuty 큐 하나에 대한 `ReceiveMessage` / `DeleteMessage` /
  `GetQueueAttributes` / `GetQueueUrl`
- Bedrock: 위 모델/Inference Profile 하나에 대한 `InvokeModel` /
  `GetInferenceProfile`
- SNS/KMS: 위 SNS Topic 하나에 대한 `Publish`, 그 Topic의 SSE-KMS 키
  (`alias/aws/sns`) 하나에 대한 `kms:GenerateDataKey*` / `kms:Decrypt`

Static AWS Credential은 어디에도 없습니다. Discord Webhook 호출은 AWS API가
아니라 일반 HTTPS POST이므로 IAM 권한과 무관하며, 현재 DEV에는 실제
Webhook URL이 아직 준비되어 있지 않습니다(아래 "Discord 통합 상태"
참고).

DEV `ConfigMap`(`k8s/overlays/dev/configmap-patch.yaml`)이 실제로 켜는
값: `MONITORING_ENABLED=true`, `SQS_GUARDDUTY_QUEUE_URL`,
`BEDROCK_REGION`/`BEDROCK_MODEL_ID`, `SNS_ALERT_TOPIC_ARN`. `k8s/base`와
`k8s/overlays/prod`에는 이 값들이 없으므로, PROD로는 DEV 설정이 새어
들어가지 않습니다(`kustomize build k8s/overlays/prod`로 확인 가능).

## 실패 / 재시도 / DLQ

"처리 순서" 단계 중 어느 하나라도 실패하면(파싱 오류, Bedrock 호출
실패/타임아웃/응답 검증 실패, Discord와 SNS 모두 Publish 실패 등
무엇이든) 메시지를 삭제하지 않습니다. 이 코드는 DLQ로 직접 메시지를
보내지 않습니다 — SQS 큐에 이미 설정된 동작만 사용합니다.

- 삭제되지 않은 메시지는 VisibilityTimeout(300초) 이후 자동으로
  재수신됩니다.
- 같은 메시지가 `maxReceiveCount`(5회)를 초과해 실패하면, 큐의
  RedrivePolicy에 따라 `dpyb-security-monitoring-guardduty-dlq-dev`로
  자동 이동합니다.
- Bedrock/Discord/SNS 오류 1건이 워커 프로세스 전체를 종료시키지
  않습니다 — 다음 메시지 처리로 넘어갑니다.
- Discord Publish가 실패(timeout/network 오류/4xx/5xx/429 등 무엇이든)
  하면 즉시 SNS로 fallback합니다 — 둘 다 실패했을 때만 메시지를
  삭제하지 않습니다. Discord가 성공하면 SNS는 호출하지 않습니다(중복
  알림 방지).
- `sample=true`(GuardDuty Sample Finding)도 건너뛰지 않고 동일하게
  전체 파이프라인을 통과합니다.

## 보안 원칙

- Static AWS Credential을 어디에도 두지 않고, IRSA만 사용합니다.
- IAM 권한은 서비스별/리소스별 최소권한으로 스코핑되어 있습니다.
- GuardDuty 원본 EventBridge 이벤트 전체나 `service.additionalInfo`
  원문을 Bedrock/Discord/SNS로 보내지 않습니다 — 정규화된 최소 필드만
  사용합니다.
- Credential/Token/Access Key/`DISCORD_WEBHOOK_URL`은 로그에 남기지
  않습니다. 실패 로그에는 `finding_id` / `finding_type` / 오류 범주만
  남기고, 성공 로그에도 분석·알림 본문 전체는 남기지 않습니다.
- Discord Webhook payload에는 항상 `allowed_mentions.parse: []`를
  고정으로 넣습니다 — GuardDuty Finding의 title/description처럼 외부에서
  흘러들어온 문자열에 `@everyone`/`@here`/사용자 멘션이 섞여 있어도 실제
  멘션이 발생하지 않도록 payload 구조 자체로 차단합니다.
- Bedrock은 분석/권고 텍스트만 생성합니다 — `risk_level`은 LLM 출력이
  아니라 GuardDuty의 공식 `severity`로부터 애플리케이션 코드가
  결정적으로 계산합니다(아래 매핑). 같은 severity는 항상 같은
  risk_level이 되어야 하고, Finding 문구로 LLM이 위험도를 낮게
  판단하도록 유도되는 경로 자체를 차단하기 위한 설계입니다.

  | severity | risk_level |
  | --- | --- |
  | 0 ≤ severity < 4 | LOW |
  | 4 ≤ severity < 7 | MEDIUM |
  | 7 ≤ severity < 9 | HIGH |
  | 9 ≤ severity ≤ 10 | CRITICAL |

- 자동 대응(remediation)은 전혀 없습니다 — 이 서비스는 탐지 결과를
  관리자에게 설명하고 권고할 뿐, 어떤 AWS 리소스도 직접 변경하지
  않습니다.
- DEV를 우선 검증하고, PROD 설정은 DEV와 분리되어 있습니다
  (Kustomize overlay, IAM Role, ConfigMap 모두 환경별로 분리).

## 실제 E2E 상태

아래 흐름이 실제 DEV 환경에서 확인되었습니다(개인정보/Finding
ID/SNS MessageId 등 구체적인 값은 기록하지 않습니다).

```
GuardDuty Sample Finding 생성
  → EventBridge
  → SQS
  → GuardDuty Parser
  → Bedrock 분석 (HIGH 판정)
  → AI 응답 검증
  → SNS Publish
  → 관리자 이메일 실제 수신
  → SQS 큐 depth 0
  → DLQ depth 0
```

확인된 Pod 상태: Running / Ready / Restart 0. 기존 서비스
(`backend-auth`, `backend-record`, `backend-book`)에 대한 회귀는
확인되지 않았습니다.

위 E2E는 SNS 알림 경로 기준입니다(당시 Discord는 아직 없었습니다).

### Discord 통합 상태

Discord Primary/SNS Fallback 로직(`app/providers/discord.py`,
`app/services/alert_message.py`의 `build_discord_payload`,
`app/services/monitoring_worker.py`)은 **코드 구현 및 단위 테스트까지
완료**되었습니다(`DISCORD_WEBHOOK_URL` 미설정 시 SNS만 쓰는 경로 포함).
다만 실제 Discord 채널/Webhook이 아직 준비되지 않아 **실제 DEV
Webhook으로의 E2E(POST 성공, 채널에 메시지 도착 확인)는 아직
수행되지 않았습니다.** Webhook이 준비되면 K8s Secret으로 URL을
주입한 뒤 별도로 검증합니다.

## 현재 구현하지 않는 것

아래는 이 서비스의 범위 밖입니다 — 향후 계획처럼 보이지 않도록 명확히
구분합니다.

- 자동 차단, 계정 잠금, Credential revoke, Security Group 자동 변경 등
  모든 자동 remediation
- Lambda 기반 자동 대응
- 자체 DB(이 서비스는 DB를 소유하지 않습니다)
- Loki / Tempo / Prometheus 신규 연동 — 아래 "Observability 범위" 참고
- PROD 운영 배포(현재는 DEV까지만 실제 운영/검증됨)

## Observability 범위

`GET /metrics`(Prometheus HTTP 메트릭), DEV `ServiceMonitor`, OTLP 기반
분산 추적 설정(`app/core/observability.py`), stdout JSON 구조화 로깅은
기존 코드 그대로 유지되고 있습니다. 다만 이번 보안관제 파이프라인
(GuardDuty → Bedrock → SNS)은 이 관측 스택을 새로 확장하지 않았습니다 —
Loki/Tempo에 대한 신규 연동이나 Prometheus 신규 메트릭 추가는 이번
구현 범위에 포함되지 않습니다.

## AWS OIDC / IAM 요구사항 (CI)

`.github/workflows/build-push-ecr.yml`은 장기 AWS Access Key(GitHub
Secrets)를 저장하지 않고, GitHub Actions OIDC + IAM Role로 ECR에
인증합니다. 브랜치별로 Role을 분리합니다.

| 항목 | DEV | PROD |
| --- | --- | --- |
| branch | `develop` | `main` |
| IAM Role | `gha-security-monitoring-ecr-dev` | `gha-security-monitoring-ecr-prod` |
| ECR | `dpyb-dev/dpyb-security-monitoring` | `dpyb-prod/dpyb-security-monitoring` |

공통: OIDC Provider `token.actions.githubusercontent.com`, Audience
`sts.amazonaws.com`, Region `ap-northeast-2`. 이 저장소의 Git 작업
자체는 AWS 리소스를 생성하지 않습니다 — 위 Role/ECR/Queue/Topic 등은
AWS 쪽에서 별도로 준비된 리소스입니다.
