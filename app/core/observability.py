"""
OpenTelemetry 분산 추적 설정
(Application -> OTLP -> OpenTelemetry Collector -> Grafana Tempo).

backend-auth(app/core/tracing.py)의 관측 인프라 패턴을 그대로 이식했다.
설계 원칙은 동일하다.

1. **관측 때문에 앱이 실패하지 않는다.** collector가 죽어 있거나 OTel
   패키지/instrumentation이 예외를 던져도 이 모듈은 그 예외를 삼키고
   애플리케이션을 정상 기동시킨다.
2. **endpoint를 하드코딩하지 않는다.** 표준 OTEL_* 환경변수만 사용한다
   (OTEL_SERVICE_NAME, OTEL_EXPORTER_OTLP_ENDPOINT,
   OTEL_RESOURCE_ATTRIBUTES). endpoint가 주입되지 않은 환경(로컬,
   pytest)에서는 tracing 전체를 켜지 않는다.
3. **W3C trace context.** 다른 MSA가 보낸 traceparent/tracestate를
   그대로 이어받는다(inbound). 전역 propagator를 명시적으로 설정해
   botocore 등이 끌어올 수 있는 AWS X-Ray propagator가 기본값을
   바꾸지 않도록 못박는다.

exporter는 OTLP http/protobuf(기본 포트 4318)를 쓴다 — 플랫폼 전체가
하나의 전송 방식을 쓰기 위함이고(backend-auth와 동일 근거), gRPC
exporter의 네이티브 의존성(grpcio)을 추가하지 않기 위함이다.

CLIAR-252 시점에는 이 서비스가 호출하는 외부 라이브러리(boto3,
DB client, outbound httpx 등)가 전혀 없으므로 라이브러리
instrumentation은 아직 아무것도 적용하지 않는다. Loki/Tempo/
Prometheus query client나 알림 client(httpx 등)를 추가하는 시점에
그 변경과 함께 opentelemetry-instrumentation-httpx 등을
requirements.txt에 넣고 _instrument_libraries()에 추가하면 된다
(backend-auth의 httpx 관련 주석과 동일한 원칙).
"""

import logging
import os

# 로그의 service 필드와 trace의 service.name이 어긋나면 Loki <-> Tempo
# 상관관계가 끊기므로, 두 곳이 같은 함수를 공유한다.
from app.core.logging_config import service_name

logger = logging.getLogger(__name__)

# FastAPI span에서 제외할 URL(정규식 부분일치). 환경변수로 덮어쓸 수 있다.
_DEFAULT_EXCLUDED_URLS = "health,metrics"

_tracing_configured = False


def tracing_enabled() -> bool:
    """OTLP endpoint가 주입되어 있고 SDK가 비활성화되지 않았는지 확인한다."""
    if os.getenv("OTEL_SDK_DISABLED", "").strip().lower() == "true":
        return False

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT"
    )
    return bool(endpoint and endpoint.strip())


def _build_resource():
    from opentelemetry.sdk.resources import Resource

    return Resource.create({"service.name": service_name()})


def _set_w3c_propagator() -> None:
    if os.getenv("OTEL_PROPAGATORS", "").strip():
        return

    from opentelemetry.baggage.propagation import W3CBaggagePropagator
    from opentelemetry.propagate import set_global_textmap
    from opentelemetry.propagators.composite import CompositePropagator
    from opentelemetry.trace.propagation.tracecontext import (
        TraceContextTextMapPropagator,
    )

    set_global_textmap(
        CompositePropagator([TraceContextTextMapPropagator(), W3CBaggagePropagator()])
    )


def _instrument(name: str, action) -> None:
    """instrumentation 하나를 적용하되, 실패해도 기동을 막지 않는다."""
    try:
        action()
    except Exception:
        logger.warning("OpenTelemetry instrumentation failed: %s", name, exc_info=True)


def configure_tracing() -> bool:
    """TracerProvider + OTLP exporter를 설정한다. 실제로 활성화됐으면 True."""
    global _tracing_configured

    if _tracing_configured:
        return True

    if not tracing_enabled():
        logger.info(
            "OpenTelemetry tracing disabled "
            "(OTEL_EXPORTER_OTLP_ENDPOINT is not configured)"
        )
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=_build_resource())
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)

        _set_w3c_propagator()
    except Exception:
        logger.error(
            "OpenTelemetry tracing setup failed; continuing without tracing",
            exc_info=True,
        )
        return False

    _instrument_libraries()

    _tracing_configured = True
    logger.info("OpenTelemetry tracing enabled (service.name=%s)", service_name())
    return True


def _instrument_libraries() -> None:
    """app 객체가 필요 없는 라이브러리 instrumentation을 적용한다.

    CLIAR-252 시점에는 계측할 외부 라이브러리 호출이 없다(모듈
    docstring 참고) — 향후 실제 provider가 추가되면 여기에 등록한다.
    """


def instrument_app(app) -> None:
    """FastAPI(ASGI) inbound HTTP instrumentation을 적용한다.

    tracing이 비활성이면 아무것도 하지 않는다(테스트/로컬에서 불필요한
    미들웨어가 끼지 않는다).
    """
    if not _tracing_configured:
        return

    def _fastapi():
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(
            app,
            excluded_urls=os.getenv(
                "OTEL_PYTHON_FASTAPI_EXCLUDED_URLS", _DEFAULT_EXCLUDED_URLS
            ),
        )

    _instrument("fastapi", _fastapi)


__all__ = ["configure_tracing", "instrument_app", "tracing_enabled"]
