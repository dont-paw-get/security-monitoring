"""
Prometheus HTTP 메트릭 노출 (관측 스택 연동: /metrics -> ServiceMonitor
-> Prometheus).

backend-auth(app/core/metrics.py)와 동일하게 Spring Boot Actuator +
Micrometer 호환 이름(`http_server_requests_seconds_*`)으로 노출한다 —
backend-book(Java/Spring Boot)이 이미 이 이름으로 메트릭을 내고 있고,
인프라의 "HTTP 5xx 에러율" / "p99 레이턴시" 알림 규칙이 이 시계열을
전제로 작성돼 있다. 이 서비스만을 위한 별도 쿼리를 인프라 쪽에 만들지
않기 위해 같은 이름/라벨 구조를 그대로 따른다.

라벨은 backend-auth와 동일하다: application(service_name과 동일),
method, uri(라우트 템플릿), status, outcome. `/health`, `/metrics`
자신은 probe/스크레이핑 트래픽이라 집계에서 제외한다.
"""

import time

from prometheus_client import CONTENT_TYPE_LATEST, Histogram, generate_latest

from app.core.logging_config import service_name

_EXCLUDED_PATHS = frozenset({"/health", "/metrics"})

HTTP_SERVER_REQUESTS = Histogram(
    "http_server_requests_seconds",
    "HTTP server request latency and count (Micrometer-compatible)",
    labelnames=("application", "method", "uri", "status", "outcome"),
)


def _outcome(status_code: int) -> str:
    if 100 <= status_code < 200:
        return "INFORMATIONAL"
    if 200 <= status_code < 300:
        return "SUCCESS"
    if 300 <= status_code < 400:
        return "REDIRECTION"
    if 400 <= status_code < 500:
        return "CLIENT_ERROR"
    return "SERVER_ERROR"


def _route_template(scope) -> str:
    route = scope.get("route")
    path = getattr(route, "path", None)
    return path or "NOT_FOUND"


def _record(scope, status_code: int, started_at: float) -> None:
    HTTP_SERVER_REQUESTS.labels(
        application=service_name(),
        method=scope.get("method", "UNKNOWN"),
        uri=_route_template(scope),
        status=str(status_code),
        outcome=_outcome(status_code),
    ).observe(time.perf_counter() - started_at)


class PrometheusMiddleware:
    """HTTP 요청마다 `http_server_requests_seconds` 히스토그램을 갱신하는
    순수 ASGI 미들웨어(backend-auth와 동일한 이유로 BaseHTTPMiddleware
    대신 순수 ASGI로 구현: 스트리밍 응답 상호작용을 피하고 scope["route"]를
    안정적으로 읽기 위함)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in _EXCLUDED_PATHS:
            await self.app(scope, receive, send)
            return

        started_at = time.perf_counter()
        status_holder = {"code": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            _record(scope, 500, started_at)
            raise

        _record(scope, status_holder["code"], started_at)


def metrics_exposition() -> tuple[bytes, str]:
    """(본문, Content-Type) 튜플. `/metrics` 핸들러가 그대로 반환한다."""
    return generate_latest(), CONTENT_TYPE_LATEST


__all__ = ["PrometheusMiddleware", "metrics_exposition", "HTTP_SERVER_REQUESTS"]
