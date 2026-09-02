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
