"""GuardDuty SQS 큐 접근 책임(CLIAR-259).

backend-record의 app/providers/(다른 서비스/AWS API 호출 client)와 같은
역할이다 — client 생성, receive_message, delete_message만 담당하고
GuardDuty Finding 파싱은 app/services/guardduty_parser.py에 둔다.

boto3는 synchronous client이므로, 호출부(app/services/monitoring_worker.py)가
asyncio.to_thread로 감싸 이벤트 루프를 막지 않는다 — 이 모듈 자체는
async가 아니다.
"""

import logging
from typing import Any

import boto3

from app.core.config import settings

logger = logging.getLogger(__name__)

# SQS 큐 자체가 이미 Long polling 20초로 설정되어 있다(Terraform/AWS
# 콘솔에서 구성됨). 여기서는 receive_message 호출 시에도 동일한 값을
# 명시해 큐 기본값에 암묵적으로 의존하지 않는다.
_WAIT_TIME_SECONDS = 20
_MAX_NUMBER_OF_MESSAGES = 10


def get_sqs_client():
    """boto3 Default Credential Provider Chain(IRSA 포함)으로 SQS client를 생성한다.

    static credential을 하드코딩하지 않는다 — EKS Pod에서는 ServiceAccount
    IRSA를 통해 자동으로 자격증명을 얻는다(app/services/s3_upload.py의
    backend-record 패턴과 동일한 원칙).
    """
    return boto3.client("sqs", region_name=settings.AWS_REGION)


def receive_messages(client=None) -> list[dict[str, Any]]:
    """GuardDuty SQS 큐에서 메시지를 long polling으로 수신한다.

    메시지가 없으면 최대 WaitTimeSeconds(20초) 대기 후 빈 목록을
    반환한다 — 이 호출 자체가 폴링 주기 역할을 하므로 호출부는 별도
    sleep 없이 바로 재호출해도 busy-loop가 되지 않는다.

    Args:
        client: 테스트나 사용자 정의 boto3 SQS client 주입용.
    """
    sqs = client or get_sqs_client()
    response = sqs.receive_message(
        QueueUrl=settings.SQS_GUARDDUTY_QUEUE_URL,
        MaxNumberOfMessages=_MAX_NUMBER_OF_MESSAGES,
        WaitTimeSeconds=_WAIT_TIME_SECONDS,
    )
    return response.get("Messages", [])


def delete_message(receipt_handle: str, client=None) -> None:
    """처리에 성공한 메시지 1건을 큐에서 삭제한다.

    호출부는 처리가 완전히 성공했을 때만 이 함수를 호출해야 한다
    (app/services/monitoring_worker.py). 실패한 메시지는 삭제하지 않고
    그대로 두면 VisibilityTimeout 이후 재수신되며, 큐에 이미 설정된
    RedrivePolicy(maxReceiveCount=5)에 따라 DLQ로 자동 이동한다 — 이
    코드에서 DLQ로 직접 SendMessage하지 않는다.

    Args:
        receipt_handle: receive_messages()가 반환한 메시지의 ReceiptHandle.
        client: 테스트나 사용자 정의 boto3 SQS client 주입용.
    """
    sqs = client or get_sqs_client()
    sqs.delete_message(QueueUrl=settings.SQS_GUARDDUTY_QUEUE_URL, ReceiptHandle=receipt_handle)
