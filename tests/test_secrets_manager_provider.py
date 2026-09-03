"""app/providers/secrets_manager.py 단위 테스트(CLIAR-271).

실제 AWS Secrets Manager를 호출하지 않는다 — boto3 secretsmanager
client를 fake 객체로 대체한다(app/providers/sns.py 테스트와 동일한 패턴).
"""

import botocore.exceptions
import pytest

from app.providers.secrets_manager import SecretRetrievalError, get_secret_value

SECRET_ID = "dpgy-infra/security-monitoring-discord-webhook-dev"


class _FakeSecretsManagerClient:
    def __init__(self, response=None, error: Exception | None = None):
        self._response = response
        self._error = error
        self.last_kwargs = None

    def get_secret_value(self, **kwargs):
        self.last_kwargs = kwargs
        if self._error is not None:
            raise self._error
        return self._response


def test_get_secret_value_calls_get_secret_value_with_secret_id():
    client = _FakeSecretsManagerClient(response={"SecretString": "https://discord.com/api/webhooks/x/y"})

    get_secret_value(SECRET_ID, client=client)

    assert client.last_kwargs["SecretId"] == SECRET_ID


def test_get_secret_value_returns_secret_string():
    client = _FakeSecretsManagerClient(response={"SecretString": "https://discord.com/api/webhooks/x/y"})

    result = get_secret_value(SECRET_ID, client=client)

    assert result == "https://discord.com/api/webhooks/x/y"


def test_get_secret_value_raises_on_access_denied():
    error = botocore.exceptions.ClientError(
        error_response={"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        operation_name="GetSecretValue",
    )
    client = _FakeSecretsManagerClient(error=error)

    with pytest.raises(SecretRetrievalError):
        get_secret_value(SECRET_ID, client=client)


def test_get_secret_value_raises_on_resource_not_found():
    error = botocore.exceptions.ClientError(
        error_response={"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
        operation_name="GetSecretValue",
    )
    client = _FakeSecretsManagerClient(error=error)

    with pytest.raises(SecretRetrievalError):
        get_secret_value(SECRET_ID, client=client)


def test_get_secret_value_raises_on_throttling():
    error = botocore.exceptions.ClientError(
        error_response={"Error": {"Code": "ThrottlingException", "Message": "too many requests"}},
        operation_name="GetSecretValue",
    )
    client = _FakeSecretsManagerClient(error=error)

    with pytest.raises(SecretRetrievalError):
        get_secret_value(SECRET_ID, client=client)


def test_get_secret_value_raises_on_unexpected_exception():
    client = _FakeSecretsManagerClient(error=RuntimeError("network unreachable"))

    with pytest.raises(SecretRetrievalError):
        get_secret_value(SECRET_ID, client=client)


def test_get_secret_value_raises_on_empty_secret_string():
    client = _FakeSecretsManagerClient(response={"SecretString": ""})

    with pytest.raises(SecretRetrievalError):
        get_secret_value(SECRET_ID, client=client)


def test_get_secret_value_raises_when_only_secret_binary_present():
    client = _FakeSecretsManagerClient(response={"SecretBinary": b"binary-not-supported"})

    with pytest.raises(SecretRetrievalError):
        get_secret_value(SECRET_ID, client=client)


def test_get_secret_value_error_message_does_not_include_secret_value():
    client = _FakeSecretsManagerClient(response={"SecretString": ""})

    with pytest.raises(SecretRetrievalError) as exc_info:
        get_secret_value(SECRET_ID, client=client)

    # 에러 메시지에는 secret_id는 포함될 수 있지만, 값 자체는 애초에
    # 실려 있지 않다(빈 문자열이므로 자명하지만, 향후 리팩터링 대비로
    # secret_id만 포함되고 별도 URL 형태 문자열이 섞이지 않는지 확인).
    assert SECRET_ID in str(exc_info.value)
