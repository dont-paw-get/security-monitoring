"""app/providers/discord.py 단위 테스트(CLIAR-271).

실제 Discord Webhook을 호출하지 않는다 — httpx client를 fake 객체로
대체한다(app/providers/sns.py 테스트와 동일한 패턴).
"""

import httpx
import pytest

from app.core.config import settings
from app.providers.discord import DiscordPublishError, publish_alert


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


def test_publish_alert_raises_when_webhook_url_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", None)
    client = _FakeHttpxClient(response=_FakeResponse(204))

    with pytest.raises(DiscordPublishError):
        publish_alert({"embeds": []}, client=client)

    assert client.last_call is None  # webhook 미설정이면 POST 자체를 시도하지 않는다


def test_publish_alert_posts_to_configured_webhook_url_with_payload(monkeypatch):
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x/y")
    client = _FakeHttpxClient(response=_FakeResponse(204))

    publish_alert({"embeds": [{"title": "t"}]}, client=client)

    url, payload = client.last_call
    assert url == "https://discord.com/api/webhooks/x/y"
    assert payload == {"embeds": [{"title": "t"}]}


def test_publish_alert_succeeds_on_2xx(monkeypatch):
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x/y")
    client = _FakeHttpxClient(response=_FakeResponse(204))

    publish_alert({"embeds": []}, client=client)  # 예외 없이 반환되어야 한다


def test_publish_alert_raises_on_429_rate_limit(monkeypatch):
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x/y")
    client = _FakeHttpxClient(response=_FakeResponse(429))

    with pytest.raises(DiscordPublishError):
        publish_alert({"embeds": []}, client=client)


def test_publish_alert_raises_on_4xx(monkeypatch):
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x/y")
    client = _FakeHttpxClient(response=_FakeResponse(400))

    with pytest.raises(DiscordPublishError):
        publish_alert({"embeds": []}, client=client)


def test_publish_alert_raises_on_5xx(monkeypatch):
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x/y")
    client = _FakeHttpxClient(response=_FakeResponse(500))

    with pytest.raises(DiscordPublishError):
        publish_alert({"embeds": []}, client=client)


def test_publish_alert_raises_on_timeout(monkeypatch):
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x/y")
    client = _FakeHttpxClient(error=httpx.TimeoutException("timed out"))

    with pytest.raises(DiscordPublishError):
        publish_alert({"embeds": []}, client=client)


def test_publish_alert_raises_on_connect_error(monkeypatch):
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x/y")
    client = _FakeHttpxClient(error=httpx.ConnectError("dns failure"))

    with pytest.raises(DiscordPublishError):
        publish_alert({"embeds": []}, client=client)
