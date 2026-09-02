# syntax=docker/dockerfile:1

FROM python:3.12-slim AS base

# 파이썬 런타임 최적화 설정
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 의존성 먼저 설치 (레이어 캐시 활용). requirements.txt의 모든 패키지가
# amd64/aarch64 wheel을 제공해 소스 컴파일이 없으므로 build-essential 등
# 추가 apt 설치는 하지 않는다(backend-auth와 동일한 근거).
COPY requirements.txt .
RUN pip install -r requirements.txt

# 애플리케이션 소스
COPY app ./app

# 비루트 사용자로 실행
RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# APP_HOST / APP_PORT 는 ConfigMap 으로 주입됨 (기본 0.0.0.0:8000)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
