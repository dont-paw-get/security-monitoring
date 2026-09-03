"""
stdout JSON 구조화 로깅 설정 (관측 스택 연동: stdout -> Grafana Alloy
-> Loki).

backend-auth(app/core/logging_config.py)의 관측 인프라 패턴을 그대로
이식했다 — 인증 도메인 로직은 없고, JSON 포매터/민감정보 마스킹/trace
상관관계 같은 공통 인프라만 가져왔다.

출력 형식(한 줄 = 하나의 JSON 객체):

    {"timestamp": "...", "level": "INFO", "service": "security-monitoring",
     "logger": "...", "message": "...", "trace_id": "...",
     "span_id": "...", <추가 필드>}

trace_id/span_id는 현재 활성 OpenTelemetry span(app/core/observability.py)
에서 가져온다. tracing이 비활성이거나 span 밖에서 남긴 로그면 null이
되며, 그 경우에도 로깅은 정상 동작한다(관측 스택 장애가 애플리케이션
동작에 영향을 주지 않는다).

민감정보 마스킹: 이 서비스는 아직 다른 MSA의 로그/이벤트를 그대로
다루지 않지만(CLIAR-252는 lifecycle 골격까지만), 향후 그 데이터를
다룰 때를 대비해 backend-auth와 동일한 2차 안전망(redact())을 미리
갖춘다 — 토큰/비밀번호/이메일 등이 실수로 로그에 흘러들어도 stdout으로
나가기 직전에 마스킹된다.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone

try:  # pragma: no cover - opentelemetry는 requirements.txt에 포함되어 있다
    from opentelemetry import trace as _otel_trace
except ImportError:  # OTel 패키지가 없어도 로깅은 동작해야 한다
    _otel_trace = None


# service 필드는 trace의 service.name(app/core/observability.py)과
# 반드시 같은 값이어야 Loki 로그와 Tempo trace를 같은 서비스로 묶을 수
# 있다. 그래서 동일한 OTEL_SERVICE_NAME 환경변수를 읽는다.
DEFAULT_SERVICE_NAME = "security-monitoring"


def service_name() -> str:
    """로그/트레이스가 공유하는 서비스 이름."""
    return os.getenv("OTEL_SERVICE_NAME", "").strip() or DEFAULT_SERVICE_NAME


# ---------------------------------------------------------------------------
# 민감정보 마스킹 (2차 안전망)
# ---------------------------------------------------------------------------

REDACTED = "[REDACTED]"

_KEY_VALUE_PATTERN = (
    r"(?i)\b("
    r"password|passwd|pwd"
    r"|secret|client_secret|secret_hash|secrethash"
    r"|access_token|accesstoken|id_token|idtoken|refresh_token|refreshtoken"
    r"|session|cookie|authorization|api_key|apikey"
    r"|aws_secret_access_key|aws_session_token"
    r")"
    r"(\s*[=:]\s*)"
    r"(\"[^\"]*\"|\'[^\']*\'|[^\s,;)}\]]+)"
)

# 순서가 중요하다. 더 구체적인 패턴(JWT, Bearer)을 먼저 적용해야
# 일반적인 key=value 패턴이 값의 일부만 잘라내는 일이 없다.
_REDACTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # JWT 전체 문자열(access token / id token). base64url "eyJ..."로
    # 시작하는 3-파트 JWT 형태는 발급 서비스와 무관하게 공통이다.
    (re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"), REDACTED),
    # Authorization 헤더 원문.
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer " + REDACTED),
    # AWS access key id / session token 앞부분.
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    # password=..., secret: "...", refresh_token=... 같은 key=value 형태.
    (re.compile(_KEY_VALUE_PATTERN), r"\1\2" + REDACTED),
    # 이메일 주소(개인정보). 로컬 파트를 통째로 지우고 도메인만 남긴다.
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"),
        REDACTED + r"@\1",
    ),
)


def redact(text: str) -> str:
    """stdout으로 나가기 직전의 로그 문자열에서 민감값을 마스킹한다."""
    for pattern, replacement in _REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# extra=로 넘어오더라도 값 자체를 통째로 버릴 키.
_DROPPED_EXTRA_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "client_secret",
        "secret_hash",
        "access_token",
        "id_token",
        "refresh_token",
        "token",
        "authorization",
        "cookie",
        "cookies",
        "session",
        "email",
        "body",
        "request_body",
        "response_body",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        # 민감정보는 아니지만 순수 노이즈. uvicorn은 모든 로그에
        # ANSI 색상 코드가 들어간 message 사본을 extra로 붙인다.
        "color_message",
    }
)

# logging.LogRecord가 항상 갖는 속성. 이 목록에 없는 속성만 호출부가
# extra=로 넣은 추가 필드로 보고 JSON에 그대로 싣는다.
_RESERVED_RECORD_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


def safe_extra(fields: dict[str, object]) -> dict[str, object]:
    """호출부가 넘긴 추가 필드에서 민감 키/LogRecord 예약 속성을 제거한다."""
    return {
        key: value
        for key, value in fields.items()
        if key.lower() not in _DROPPED_EXTRA_KEYS
        and key not in _RESERVED_RECORD_ATTRS
        and not key.startswith("_")
    }


# ---------------------------------------------------------------------------
# trace 상관관계
# ---------------------------------------------------------------------------


def current_trace_ids() -> tuple[str | None, str | None]:
    """현재 활성 span의 (trace_id, span_id)를 W3C 16진 표기로 반환한다."""
    if _otel_trace is None:
        return None, None
    try:
        context = _otel_trace.get_current_span().get_span_context()
        if not context.is_valid:
            return None, None
        return format(context.trace_id, "032x"), format(context.span_id, "016x")
    except Exception:  # pragma: no cover - 방어적
        return None, None


# ---------------------------------------------------------------------------
# 포매터
# ---------------------------------------------------------------------------


class JsonLogFormatter(logging.Formatter):
    """LogRecord 한 건을 한 줄 JSON으로 직렬화한다(Alloy/Loki 수집용)."""

    def format(self, record: logging.LogRecord) -> str:
        trace_id, span_id = current_trace_ids()

        timestamp = (
            datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

        payload: dict[str, object] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "service": service_name(),
            "logger": record.name,
            "message": redact(record.getMessage()),
            "trace_id": trace_id,
            "span_id": span_id,
        }

        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        if record.stack_info:
            payload["stack"] = redact(self.formatStack(record.stack_info))

        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_ATTRS or key.startswith("_"):
                continue
            if key in payload or key.lower() in _DROPPED_EXTRA_KEYS:
                continue
            payload[key] = redact(value) if isinstance(value, str) else value

        return json.dumps(payload, ensure_ascii=False, default=str)


TEXT_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


class RedactingTextFormatter(logging.Formatter):
    """로컬 개발용 사람이 읽는 포맷(LOG_FORMAT=text)."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


# ---------------------------------------------------------------------------
# 설정 진입점
# ---------------------------------------------------------------------------

# uvicorn은 애플리케이션 모듈을 import하기 **전에** 자기 로거
# (uvicorn/uvicorn.error/uvicorn.access)에 propagate=False로 핸들러를
# 달아둔다. configure_logging()은 uvicorn 이후에 실행되므로(app.main
# import 시점), 이 로거들의 핸들러를 떼고 root로 흘려보내 모든 로그를
# 하나의 JSON 스트림으로 통일한다.
_MANAGED_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


def configure_logging(level: str | None = None, fmt: str | None = None) -> None:
    """root logger에 stdout JSON 핸들러를 설정한다.

    level/fmt를 생략하면 settings.LOG_LEVEL / settings.LOG_FORMAT를
    사용한다(app/core/config.py). 여러 번 호출해도 핸들러가 중복
    누적되지 않는다.
    """
    from app.core.config import settings

    resolved_level = (level or settings.LOG_LEVEL).upper()
    resolved_format = (fmt or settings.LOG_FORMAT).lower()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonLogFormatter()
        if resolved_format == "json"
        else RedactingTextFormatter(TEXT_FORMAT)
    )

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(resolved_level)

    for name in _MANAGED_LOGGERS:
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True

    # OTLP collector가 죽어 있으면 exporter가 재시도마다 로그를 남긴다.
    # 애플리케이션 동작에 영향이 없으므로 ERROR만 남겨 로그 스트림이
    # 넘치지 않게 한다.
    logging.getLogger("opentelemetry").setLevel(logging.ERROR)
