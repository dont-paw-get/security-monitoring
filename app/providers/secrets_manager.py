"""AWS Secrets Manager 접근 책임(CLIAR-271).

app/providers/sqs.py, app/providers/bedrock.py, app/providers/sns.py와
동일한 역할 분리 원칙 — client 생성과 단일 API 호출(GetSecretValue)만
담당한다. 언제 조회하고 결과를 어떻게 캐싱할지는 호출부
(app/services/monitoring_worker.py)의 책임이다 — 이 모듈 자체는 호출될
때마다 항상 실제 API를 호출한다(캐싱하지 않는다).

boto3는 synchronous client이므로, 호출부가 asyncio.to_thread로 감싸
이벤트 루프를 막지 않는다 — 이 모듈 자체는 async가 아니다.
"""
import logging

import boto3
import botocore.exceptions

from app.core.config import settings

logger = logging.getLogger(__name__)


class SecretRetrievalError(Exception):
    """Secret 조회가 실패한 경우(AccessDenied/ResourceNotFound/Throttling/
    network 오류/SecretString 없음/빈 값 등). 예외 메시지에는 secret_id만
    포함한다 — Secret 값은 절대 포함하지 않는다."""


def get_secrets_manager_client():
    """boto3 기본 Credential Provider Chain(IRSA 포함)으로 client를 생성한다.

    static credential을 코드/설정에 하드코딩하지 않는다.
    """
    return boto3.client("secretsmanager", region_name=settings.AWS_REGION)


def get_secret_value(secret_id: str, client=None) -> str:
    """Secrets Manager에서 문자열 Secret 값(SecretString)을 조회한다.

    이번 Secret(Discord Webhook URL)은 raw string이므로 SecretString만
    지원한다 — SecretBinary만 있는 응답은 실패로 처리한다.

    Args:
        secret_id: Secret 이름 또는 ARN.
        client: 테스트나 사용자 정의 boto3 client 주입용.

    Raises:
        SecretRetrievalError: AWS SDK 호출 실패, SecretString이 없거나
            빈 문자열인 경우.
    """
    sm = client or get_secrets_manager_client()

    try:
        response = sm.get_secret_value(SecretId=secret_id)
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "ClientError")
        logger.warning(
            "secrets manager get_secret_value failed with %s (secret_id=%s)",
            error_code,
            secret_id,
        )
        raise SecretRetrievalError(
            f"Secrets Manager get_secret_value failed: {error_code} (secret_id={secret_id})"
        ) from exc
    except Exception as exc:
        logger.warning(
            "secrets manager get_secret_value failed unexpectedly: %s (secret_id=%s)",
            type(exc).__name__,
            secret_id,
        )
        raise SecretRetrievalError(
            f"Secrets Manager get_secret_value failed unexpectedly (secret_id={secret_id})"
        ) from exc

    secret_string = response.get("SecretString")
    if not secret_string:
        raise SecretRetrievalError(
            f"Secret has no usable SecretString (empty or SecretBinary-only, secret_id={secret_id})"
        )

    return secret_string
