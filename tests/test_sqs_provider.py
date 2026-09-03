"""app/providers/sqs.py 단위 테스트(CLIAR-259).

실제 AWS S3/SQS를 호출하지 않는다 — Mock 클라이언트를 주입해 호출
파라미터(QueueUrl/MaxNumberOfMessages/WaitTimeSeconds/ReceiptHandle)만
검증한다.
"""

from unittest.mock import MagicMock

from app.core.config import settings
from app.providers import sqs as sqs_provider


def test_receive_messages_calls_expected_parameters():
    fake_client = MagicMock()
    fake_client.receive_message.return_value = {"Messages": [{"Body": "{}", "ReceiptHandle": "r1"}]}

    messages = sqs_provider.receive_messages(client=fake_client)

    assert messages == [{"Body": "{}", "ReceiptHandle": "r1"}]
    fake_client.receive_message.assert_called_once_with(
        QueueUrl=settings.SQS_GUARDDUTY_QUEUE_URL,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=20,
    )


def test_receive_messages_returns_empty_list_when_no_messages():
    fake_client = MagicMock()
    fake_client.receive_message.return_value = {}  # Messages 키 자체가 없는 정상 응답

    messages = sqs_provider.receive_messages(client=fake_client)

    assert messages == []


def test_delete_message_calls_expected_parameters():
    fake_client = MagicMock()

    sqs_provider.delete_message("receipt-handle-123", client=fake_client)

    fake_client.delete_message.assert_called_once_with(
        QueueUrl=settings.SQS_GUARDDUTY_QUEUE_URL,
        ReceiptHandle="receipt-handle-123",
    )
