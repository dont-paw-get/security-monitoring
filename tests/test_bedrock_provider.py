"""app/providers/bedrock.py 단위 테스트(CLIAR-264).

실제 AWS Bedrock을 호출하지 않는다 — boto3 bedrock-runtime client를
fake 객체로 대체한다(app/providers/sqs.py 테스트와 동일한 패턴).
"""

import botocore.exceptions
import pytest

from app.providers.bedrock import BedrockInvokeError, invoke_model


class _FakeBedrockClient:
    def __init__(self, response=None, error: Exception | None = None):
        self._response = response
        self._error = error
        self.last_kwargs = None

    def converse(self, **kwargs):
        self.last_kwargs = kwargs
        if self._error is not None:
            raise self._error
        return self._response


def _converse_response(text: str) -> dict:
    return {"output": {"message": {"content": [{"text": text}]}}}


def test_invoke_model_calls_converse_with_model_id_and_prompt():
    client = _FakeBedrockClient(response=_converse_response('{"ok": true}'))

    invoke_model("분석해줘", client=client)

    assert client.last_kwargs["messages"][0]["content"][0]["text"] == "분석해줘"
    assert "modelId" in client.last_kwargs
    # non-streaming converse만 사용한다 — bedrock:InvokeModelWithResponseStream
    # 권한이 없으므로 converse_stream 계열 kwargs가 섞이지 않아야 한다.
    assert "inferenceConfig" in client.last_kwargs


def test_invoke_model_returns_response_text():
    client = _FakeBedrockClient(response=_converse_response("hello world"))

    result = invoke_model("prompt", client=client)

    assert result == "hello world"


def test_invoke_model_raises_on_aws_client_error():
    error = botocore.exceptions.ClientError(
        error_response={"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        operation_name="Converse",
    )
    client = _FakeBedrockClient(error=error)

    with pytest.raises(BedrockInvokeError):
        invoke_model("prompt", client=client)


def test_invoke_model_raises_on_throttling_error():
    error = botocore.exceptions.ClientError(
        error_response={"Error": {"Code": "ThrottlingException", "Message": "too many requests"}},
        operation_name="Converse",
    )
    client = _FakeBedrockClient(error=error)

    with pytest.raises(BedrockInvokeError):
        invoke_model("prompt", client=client)


def test_invoke_model_raises_on_missing_text_content():
    client = _FakeBedrockClient(response={"output": {"message": {"content": []}}})

    with pytest.raises(BedrockInvokeError):
        invoke_model("prompt", client=client)


def test_invoke_model_raises_on_empty_text():
    client = _FakeBedrockClient(response=_converse_response("   "))

    with pytest.raises(BedrockInvokeError):
        invoke_model("prompt", client=client)


def test_invoke_model_raises_on_unexpected_exception():
    client = _FakeBedrockClient(error=RuntimeError("network unreachable"))

    with pytest.raises(BedrockInvokeError):
        invoke_model("prompt", client=client)
