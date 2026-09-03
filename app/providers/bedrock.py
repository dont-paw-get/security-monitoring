"""Bedrock Runtime 접근 책임(CLIAR-264).

app/providers/sqs.py와 동일한 역할 분리 원칙 — client 생성 + Converse
호출 + 텍스트 응답 추출만 담당한다. GuardDuty Finding을 분석용 프롬프트로
바꾸는 로직과 AI 응답을 검증하는 로직은 app/services/security_analysis.py
에 둔다.

boto3는 synchronous client이므로, 호출부(app/services/monitoring_worker.py)
가 asyncio.to_thread로 감싸 이벤트 루프를 막지 않는다 — 이 모듈 자체는
async가 아니다.

Runtime IAM(dpyb-security-monitoring-irsa-dev)은 bedrock:InvokeModel과
bedrock:GetInferenceProfile만 가지고 있다(특정 Inference Profile/모델로
스코핑됨). converse_stream()이 요구하는 bedrock:InvokeModelWithResponseStream
권한은 없으므로, 반드시 non-streaming converse()만 사용한다.
"""
import logging

import boto3
import botocore.exceptions

from app.core.config import settings

logger = logging.getLogger(__name__)

_MAX_OUTPUT_TOKENS = 1024
_TEMPERATURE = 0.0


class BedrockInvokeError(Exception):
    """Bedrock Converse 호출이 실패한 경우(AWS SDK 오류/빈 응답 등)."""


def get_bedrock_runtime_client():
    """boto3 기본 Credential Provider Chain(IRSA 포함)으로 client를 생성한다.

    static credential을 코드/설정에 하드코딩하지 않는다.
    """
    return boto3.client("bedrock-runtime", region_name=settings.BEDROCK_REGION)


def invoke_model(prompt: str, client=None) -> str:
    """Bedrock Converse API를 호출하고 모델 응답 텍스트를 반환한다.

    Args:
        prompt: 사용자 메시지로 전달할 프롬프트 전문.
        client: 테스트나 사용자 정의 boto3 bedrock-runtime client 주입용.

    Raises:
        BedrockInvokeError: AWS SDK 호출 실패, 또는 응답에 텍스트가 없는 경우.
    """
    bedrock = client or get_bedrock_runtime_client()

    try:
        response = bedrock.converse(
            modelId=settings.BEDROCK_MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={
                "maxTokens": _MAX_OUTPUT_TOKENS,
                "temperature": _TEMPERATURE,
            },
        )
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "ClientError")
        logger.warning("bedrock converse failed with %s", error_code)
        raise BedrockInvokeError(f"Bedrock invoke failed: {error_code}") from exc
    except Exception as exc:
        logger.warning("bedrock converse failed unexpectedly: %s", type(exc).__name__)
        raise BedrockInvokeError("Bedrock invoke failed") from exc

    try:
        content_list = response["output"]["message"]["content"]
        text = content_list[0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise BedrockInvokeError("Bedrock response missing text content") from exc

    if not text or not text.strip():
        raise BedrockInvokeError("Bedrock returned empty text")

    return text
