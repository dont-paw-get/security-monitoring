"""app/providers/discord.py 단위 테스트(CLIAR-271, CLIAR-271 Secrets
Manager 연동 이후 publish_alert(webhook_url, payload, client=...) 시그니처).

실제 Discord Webhook을 호출하지 않는다 — httpx client를 fake 객체로
대체한다(app/providers/sns.py 테스트와 동일한 패턴).
"""

import httpx
import pytest

from app.providers.discord import DiscordPublishError, publish_alert

WEBHOOK_URL = "https://discord.com/api/webhooks/x/y"


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeHttpxClient:
    def __init__(self, response: _FakeResponse | None = None, error: Exception | None = None):
        self._response = response
        self._error = error
        self.last_call = None

    def post(self, url, json=None):
        self.last_call = (url, json)
        if self._error is not None:
            raise self._error
        return self._response


def test_publish_alert_raises_when_webhook_url_is_empty():
    client = _FakeHttpxClient(response=_FakeResponse(204))

    with pytest.raises(DiscordPublishError):
        publish_alert("", {"embeds": []}, client=client)

    assert client.last_call is None  # webhook_url이 비어 있으면 POST 자체를 시도하지 않는다


def test_publish_alert_posts_to_given_webhook_url_with_payload():
    client = _FakeHttpxClient(response=_FakeResponse(204))

    publish_alert(WEBHOOK_URL, {"embeds": [{"title": "t"}]}, client=client)

    url, payload = client.last_call
    assert url == WEBHOOK_URL
    assert payload == {"embeds": [{"title": "t"}]}


def test_publish_alert_succeeds_on_2xx():
    client = _FakeHttpxClient(response=_FakeResponse(204))

    publish_alert(WEBHOOK_URL, {"embeds": []}, client=client)  # 예외 없이 반환되어야 한다


def test_publish_alert_raises_on_429_rate_limit():
    client = _FakeHttpxClient(response=_FakeResponse(429))

    with pytest.raises(DiscordPublishError):
        publish_alert(WEBHOOK_URL, {"embeds": []}, client=client)


def test_publish_alert_raises_on_4xx():
    client = _FakeHttpxClient(response=_FakeResponse(400))

    with pytest.raises(DiscordPublishError):
        publish_alert(WEBHOOK_URL, {"embeds": []}, client=client)


def test_publish_alert_raises_on_5xx():
    client = _FakeHttpxClient(response=_FakeResponse(500))

    with pytest.raises(DiscordPublishError):
        publish_alert(WEBHOOK_URL, {"embeds": []}, client=client)


def test_publish_alert_raises_on_timeout():
    client = _FakeHttpxClient(error=httpx.TimeoutException("timed out"))

    with pytest.raises(DiscordPublishError):
        publish_alert(WEBHOOK_URL, {"embeds": []}, client=client)


def test_publish_alert_raises_on_connect_error():
    client = _FakeHttpxClient(error=httpx.ConnectError("dns failure"))

    with pytest.raises(DiscordPublishError):
        publish_alert(WEBHOOK_URL, {"embeds": []}, client=client)


def test_publish_alert_error_message_does_not_include_webhook_url():
    client = _FakeHttpxClient(response=_FakeResponse(500))

    with pytest.raises(DiscordPublishError) as exc_info:
        publish_alert(WEBHOOK_URL, {"embeds": []}, client=client)

    assert WEBHOOK_URL not in str(exc_info.value)
