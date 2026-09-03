"""
CLIAR-259: GuardDuty SQS Consumer.

MONITORING_ENABLED=false(기본값, app/core/config.py)면 아무 것도 하지
않는다 — 앱은 워커 없이도 정상 기동/종료된다(boto3 client 생성/AWS API
호출/polling이 전혀 발생하지 않는다). true이면 GuardDuty SQS 큐를 long
polling으로 소비한다:

    receive -> Body JSON parse -> GuardDuty Finding 정규화
    -> (성공) 구조화 로그 -> DeleteMessage
    -> (실패) 삭제하지 않음 -> VisibilityTimeout 후 재시도
       -> maxReceiveCount(5) 초과 시 큐의 기존 RedrivePolicy가 DLQ로 이동

이 코드는 DLQ로 직접 SendMessage하지 않는다 — SQS 자체의
RedrivePolicy만 사용한다.

이 티켓 범위: SQS Consumer + GuardDuty Finding Parser까지만. Bedrock
분석/SNS 알림은 아직 구현하지 않는다 — 파싱/정규화가 성공하면 구조화
로그를 남기는 것으로 "현재 단계의 처리 성공"을 정의한다(item 8).
"""

import asyncio
import json
import logging

from app.core.config import settings
from app.providers import sqs as sqs_provider
from app.services.guardduty_parser import GuardDutyEventError, parse_guardduty_event

logger = logging.getLogger(__name__)

# receive_message 자체가 SQS 서버 측에서 최대 WaitTimeSeconds(20초) 동안
# 대기하므로, 정상 흐름(빈 결과 포함)에서는 이 호출 자체가 폴링 주기
# 역할을 한다. 아래 backoff는 receive_message가 예외로 실패했을 때만
# 쓰는 짧은 재시도 대기이며, busy-loop를 막기 위한 것이다.
_ERROR_BACKOFF_SECONDS = 5.0

# 로그에 남길 GuardDuty Finding 필드(item 8): 이 다섯 개만 남기고, 원본
# Finding 전체(JSON)나 title/description 등 그 외 필드는 로그에 넣지
# 않는다.
_LOGGED_FINDING_FIELDS = ("finding_id", "finding_type", "severity", "region", "sample")


class MonitoringWorker:
    """GuardDuty SQS Consumer의 lifecycle만 관리한다(receive/parse/delete 로직은
    각각 app/providers/sqs.py, app/services/guardduty_parser.py에 위임)."""

    def __init__(self, backoff_seconds: float = _ERROR_BACKOFF_SECONDS) -> None:
        self._backoff_seconds = backoff_seconds
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """MONITORING_ENABLED가 false면 아무 것도 하지 않는다.

        MONITORING_ENABLED=true인데 SQS_GUARDDUTY_QUEUE_URL이 없는
        설정 오류 상태에서는, 애플리케이션을 죽이지 않고 에러 로그만
        남긴 뒤 polling을 시작하지 않는다.
        """
        if not settings.MONITORING_ENABLED:
            logger.info("monitoring worker disabled (MONITORING_ENABLED=false)")
            return
        if not settings.SQS_GUARDDUTY_QUEUE_URL:
            logger.error(
                "monitoring worker cannot start: SQS_GUARDDUTY_QUEUE_URL is not configured"
            )
            return
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name="monitoring-worker")
        logger.info("monitoring worker started (guardduty sqs consumer)")

    async def stop(self) -> None:
        """실행 중인 태스크를 취소하고 정상적으로 종료를 기다린다."""
        if self._task is None:
            return
        task, self._task = self._task, None
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        logger.info("monitoring worker stopped")

    async def _run(self) -> None:
        try:
            while True:
                await self._run_once()
        except asyncio.CancelledError:
            raise

    async def _run_once(self) -> None:
        """SQS long polling 1회 + 수신한 메시지 전부 처리.

        boto3는 synchronous client이므로 asyncio.to_thread로 감싸 이벤트
        루프를 막지 않는다. receive_message 예외 1건이 worker 전체를
        종료시키지 않도록 여기서 잡고, 무한 빠른 retry가 되지 않도록
        짧은 backoff 후 다음 반복으로 넘어간다.
        """
        try:
            messages = await asyncio.to_thread(sqs_provider.receive_messages)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("sqs receive_message failed", exc_info=True)
            await asyncio.sleep(self._backoff_seconds)
            return

        for message in messages:
            await self._process_message(message)

    async def _process_message(self, message: dict) -> None:
        """메시지 1건을 처리하고, 처리가 성공했을 때만 삭제한다(at-least-once)."""
        receipt_handle = message.get("ReceiptHandle")
        success = self._handle_body(message.get("Body"))

        if not success or not receipt_handle:
            return

        try:
            await asyncio.to_thread(sqs_provider.delete_message, receipt_handle)
        except asyncio.CancelledError:
            raise
        except Exception:
            # 삭제 실패 시 메시지가 재수신될 수 있다 — at-least-once를
            # 전제로 하며, 이번 단계에서는 별도 idempotency 저장소를
            # 추가하지 않는다(item 10).
            logger.warning("sqs delete_message failed", exc_info=True)

    def _handle_body(self, body: str | None) -> bool:
        """SQS 메시지 Body(JSON 문자열)를 파싱/정규화하고 성공 시 구조화 로그를 남긴다.

        Returns:
            처리 성공 여부. False면 호출부가 메시지를 삭제하지 않는다
            (JSON parsing 실패, GuardDuty 이벤트 구조 오류 모두 포함).
        """
        if body is None:
            logger.warning("sqs message has no body")
            return False

        try:
            event = json.loads(body)
        except (TypeError, ValueError):
            logger.warning("sqs message body is not valid JSON")
            return False

        try:
            finding = parse_guardduty_event(event)
        except GuardDutyEventError as exc:
            logger.warning("guardduty event is malformed: %s", exc)
            return False

        finding_fields = finding.model_dump()
        logger.info(
            "guardduty finding processed",
            extra={key: finding_fields[key] for key in _LOGGED_FINDING_FIELDS},
        )
        return True


# FastAPI lifespan(app/main.py)이 공유하는 단일 인스턴스.
monitoring_worker = MonitoringWorker()
