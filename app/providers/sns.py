"""SNS 관리자 알림 발행 책임(CLIAR-268).

app/providers/sqs.py, app/providers/bedrock.py와 동일한 역할 분리 원칙 —
client 생성과 Publish 호출만 담당한다. 알림 본문/제목 포맷은
app/services/alert_message.py에 둔다.

boto3는 synchronous client이므로, 호출부(app/services/monitoring_worker.py)
가 asyncio.to_thread로 감싸 이벤트 루프를 막지 않는다 — 이 모듈 자체는
async가 아니다.

Runtime IAM(dpyb-security-monitoring-irsa-dev)은 이 Topic 하나에 대한
sns:Publish와, alias/aws/sns 실제 Key 하나에 대한 kms:GenerateDataKey*/
kms:Decrypt만 가지고 있다(CLIAR-268 사전 작업).
"""
import logging

import boto3
import botocore.exceptions

from app.core.config import settings

logger = logging.getLogger(__name__)


class SnsPublishError(Exception):
    """SNS Publish 호출이 실패한 경우(AWS SDK 오류/응답 이상 등)."""


def get_sns_client():
    """boto3 기본 Credential Provider Chain(IRSA 포함)으로 client를 생성한다.

    static credential을 코드/설정에 하드코딩하지 않는다.
    """
    return boto3.client("sns", region_name=settings.AWS_REGION)


def publish_alert(subject: str, message: str, client=None) -> str:
    """SNS Topic에 관리자 알림을 발행하고 MessageId를 반환한다.

    Args:
        subject: SNS Subject.
        message: 알림 본문(app/services/alert_message.py가 구성).
        client: 테스트나 사용자 정의 boto3 SNS client 주입용.

    Raises:
        SnsPublishError: AWS SDK 호출 실패(AccessDenied, KMS 관련 오류,
            Throttling 등 포함)이거나 응답에 MessageId가 없는 경우.
    """
    sns = client or get_sns_client()

    try:
        response = sns.publish(
            TopicArn=settings.SNS_ALERT_TOPIC_ARN,
            Subject=subject,
            Message=message,
        )
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "ClientError")
        logger.warning("sns publish failed with %s", error_code)
        raise SnsPublishError(f"SNS publish failed: {error_code}") from exc
    except Exception as exc:
        logger.warning("sns publish failed unexpectedly: %s", type(exc).__name__)
        raise SnsPublishError("SNS publish failed") from exc

    message_id = response.get("MessageId")
    if not message_id:
        raise SnsPublishError("SNS publish response missing MessageId")

    return message_id
