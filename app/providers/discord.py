"""Discord Webhook 알림 발행 책임(CLIAR-271, CLIAR-271 Secrets Manager 연동).

app/providers/sqs.py, app/providers/bedrock.py, app/providers/sns.py와
동일한 역할 분리 원칙 — client 생성과 HTTP POST 호출만 담당한다. embed
payload 구성은 app/services/alert_message.py에 둔다.

이 모듈은 Webhook URL의 출처를 모른다 — 호출부
(app/services/monitoring_worker.py)가 DISCORD_WEBHOOK_URL 환경변수 또는
AWS Secrets Manager(DISCORD_WEBHOOK_SECRET_ID,
app/providers/secrets_manager.py)에서 미리 확인한 URL을 인자로 전달한다.
Secrets Manager 도입 전에는 이 함수가 직접 settings.DISCORD_WEBHOOK_URL을
읽었지만, URL 공급 방식이 늘어나면서 호출부 책임으로 옮겼다 — 알림 전송
경로(HTTP POST) 자체는 그대로다.

Discord Bot/SDK를 쓰지 않고 Incoming Webhook에 순수 HTTP POST만 한다.
httpx는 이미 requirements.txt에 있던 의존성이다(FastAPI TestClient가
내부적으로 필요로 함) — 새 라이브러리를 추가하지 않는다.

이 모듈은 boto3 provider들과 마찬가지로 동기(sync)다 — 호출부가
asyncio.to_thread로 감싸 이벤트 루프를 막지 않는다.

Webhook URL은 Secret이므로 어떤 로그/예외 메시지에도 남기지 않는다.
"""
import logging

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 5.0


class DiscordPublishError(Exception):
    """Discord Webhook 호출이 실패한 경우(URL 없음/HTTP 오류/timeout/network 오류 등)."""


def get_discord_client() -> httpx.Client:
    return httpx.Client(timeout=_TIMEOUT_SECONDS)


def publish_alert(webhook_url: str, payload: dict, client: httpx.Client | None = None) -> None:
    """Discord Incoming Webhook으로 payload를 POST한다.

    Args:
        webhook_url: 실제 Discord Incoming Webhook URL. 호출부가
            DISCORD_WEBHOOK_URL 또는 Secrets Manager에서 미리 확인한
            값을 넘긴다.
        payload: app/services/alert_message.py의 build_discord_payload()가
            구성한 embed payload.
        client: 테스트나 사용자 정의 httpx client 주입용.

    Raises:
        DiscordPublishError: webhook_url이 비어 있거나, HTTP 요청이
            실패(timeout/network 오류/4xx/5xx/429 등)한 경우.
    """
    if not webhook_url:
        raise DiscordPublishError("webhook_url is empty")

    owns_client = client is None
    http_client = client or get_discord_client()

    try:
        response = http_client.post(webhook_url, json=payload)
    except httpx.HTTPError as exc:
        logger.warning("discord webhook request failed: %s", type(exc).__name__)
        raise DiscordPublishError(f"Discord webhook request failed: {type(exc).__name__}") from exc
    finally:
        if owns_client:
            http_client.close()

    # Incoming Webhook 성공 응답은 보통 204(No Content)이고, wait=true
    # 쿼리를 쓰면 200과 함께 메시지 객체가 온다 — 2xx 전체를 성공으로
    # 취급한다. 429(rate limit)를 포함한 그 외 상태 코드는 모두 실패로
    # 처리해 SNS fallback으로 넘긴다.
    if response.status_code >= 300:
        logger.warning("discord webhook returned HTTP %s", response.status_code)
        raise DiscordPublishError(f"Discord webhook returned HTTP {response.status_code}")
