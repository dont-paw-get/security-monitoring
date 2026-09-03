"""app/providers/sns.py 단위 테스트(CLIAR-268).

실제 AWS SNS를 호출하지 않는다 — boto3 SNS client를 fake 객체로
대체한다(app/providers/bedrock.py 테스트와 동일한 패턴).
"""

import botocore.exceptions
import pytest

from app.providers.sns import SnsPublishError, publish_alert


class _FakeSnsClient:
    def __init__(self, response=None, error: Exception | None = None):
        self._response = response
        self._error = error
        self.last_kwargs = None

    def publish(self, **kwargs):
        self.last_kwargs = kwargs
        if self._error is not None:
            raise self._error
        return self._response


def test_publish_alert_calls_publish_with_topic_subject_message():
    client = _FakeSnsClient(response={"MessageId": "msg-1"})

    publish_alert("제목", "본문", client=client)

    assert client.last_kwargs["Subject"] == "제목"
    assert client.last_kwargs["Message"] == "본문"
    assert "TopicArn" in client.last_kwargs


def test_publish_alert_returns_message_id():
    client = _FakeSnsClient(response={"MessageId": "msg-123"})

    result = publish_alert("제목", "본문", client=client)

    assert result == "msg-123"


def test_publish_alert_raises_on_access_denied():
    error = botocore.exceptions.ClientError(
        error_response={"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        operation_name="Publish",
    )
    client = _FakeSnsClient(error=error)

    with pytest.raises(SnsPublishError):
        publish_alert("제목", "본문", client=client)


def test_publish_alert_raises_on_kms_access_denied():
    error = botocore.exceptions.ClientError(
        error_response={"Error": {"Code": "KMSAccessDeniedException", "Message": "kms denied"}},
        operation_name="Publish",
    )
    client = _FakeSnsClient(error=error)

    with pytest.raises(SnsPublishError):
        publish_alert("제목", "본문", client=client)


def test_publish_alert_raises_on_throttling():
    error = botocore.exceptions.ClientError(
        error_response={"Error": {"Code": "ThrottlingException", "Message": "too many requests"}},
        operation_name="Publish",
    )
    client = _FakeSnsClient(error=error)

    with pytest.raises(SnsPublishError):
        publish_alert("제목", "본문", client=client)


def test_publish_alert_raises_on_missing_message_id():
    client = _FakeSnsClient(response={})

    with pytest.raises(SnsPublishError):
        publish_alert("제목", "본문", client=client)


def test_publish_alert_raises_on_unexpected_exception():
    client = _FakeSnsClient(error=RuntimeError("network unreachable"))

    with pytest.raises(SnsPublishError):
        publish_alert("제목", "본문", client=client)
