from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.health import router as health_router
from app.api.metrics import router as metrics_router
from app.core.logging_config import configure_logging
from app.core.metrics import PrometheusMiddleware
from app.core.observability import configure_tracing, instrument_app
from app.services.monitoring_worker import monitoring_worker

# 관측 설정은 app 객체를 만들기 전에 마친다(backend-auth와 동일한 순서).
#
# configure_logging(): root logger에 stdout JSON 핸들러를 단다. uvicorn이
#   이 모듈을 import한 뒤에 실행되므로, uvicorn이 미리 달아둔 평문 핸들러를
#   걷어내고 로그 스트림을 하나로 통일할 수 있다.
# configure_tracing(): OTLP endpoint가 주입된 환경에서만 TracerProvider를
#   켠다. FastAPI inbound 계측만은 app 객체가 필요하므로 아래
#   instrument_app(app)에서 한다. 실패해도 예외를 밖으로 내보내지 않는다.
configure_logging()
configure_tracing()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """모니터링 워커의 시작/정상 종료를 앱 lifecycle에 연동한다.

    MONITORING_ENABLED=false(기본값)면 monitoring_worker.start()는
    아무 것도 하지 않고 즉시 반환한다 — 워커가 꺼져 있어도 앱은
    정상적으로 기동/종료된다(app/services/monitoring_worker.py).
    """
    await monitoring_worker.start()
    try:
        yield
    finally:
        await monitoring_worker.stop()


app = FastAPI(title="security-monitoring", lifespan=lifespan)

# Prometheus HTTP 메트릭(app/core/metrics.py). tracing과 달리 외부
# 의존성이 없으므로 항상 켜져 있다.
app.add_middleware(PrometheusMiddleware)

# FastAPI(ASGI) inbound instrumentation. tracing이 비활성이면 아무
# 미들웨어도 추가되지 않는다.
instrument_app(app)

app.include_router(health_router)
app.include_router(metrics_router)
