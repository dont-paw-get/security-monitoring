"""
CLIAR-259/264: GuardDuty SQS Consumer + Bedrock AI 분석.

MONITORING_ENABLED=false(기본값, app/core/config.py)면 아무 것도 하지
않는다 — 앱은 워커 없이도 정상 기동/종료된다(boto3 client 생성/AWS API
호출/polling이 전혀 발생하지 않는다). true이면 GuardDuty SQS 큐를 long
polling으로 소비한다:

    receive -> Body JSON parse -> GuardDuty Finding 정규화
    -> Bedrock AI 분석(app/services/security_analysis.py) -> 응답 검증
    -> (성공) 구조화 로그 -> DeleteMessage
    -> (실패) 삭제하지 않음 -> VisibilityTimeout 후 재시도
       -> maxReceiveCount(5) 초과 시 큐의 기존 RedrivePolicy가 DLQ로 이동

CLIAR-264 핵심 규칙: Bedrock 분석이 성공하고 응답이 스키마를 통과해야만
"처리 성공"이며, 그때만 DeleteMessage를 호출한다. GuardDuty 파싱까지만
성공하고 Bedrock 분석이 실패한 경우(AWS 오류/타임아웃/malformed 응답 등
무엇이든)에도 메시지를 삭제하지 않는다 — 기존 재시도/DLQ 동작을 그대로
따른다.

이 코드는 DLQ로 직접 SendMessage하지 않는다 — SQS 자체의
RedrivePolicy만 사용한다.
"""

import asyncio
import json
import logging

from app.core.config import settings
from app.providers import sqs as sqs_provider
from app.services.guardduty_parser import GuardDutyEventError, parse_guardduty_event
from app.services.security_analysis import SecurityAnalysisError, analyze_finding

logger = logging.getLogger(__name__)

# receive_message 자체가 SQS 서버 측에서 최대 WaitTimeSeconds(20초) 동안
# 대기하므로, 정상 흐름(빈 결과 포함)에서는 이 호출 자체가 폴링 주기
# 역할을 한다. 아래 backoff는 receive_message가 예외로 실패했을 때만
# 쓰는 짧은 재시도 대기이며, busy-loop를 막기 위한 것이다.
_ERROR_BACKOFF_SECONDS = 5.0

# 성공 로그에 남길 필드(item 15): finding_id/finding_type/severity/region/
# sample은 Finding에서, risk_level은 분석 결과에서 가져온다. summary/
# cause/impact/recommended_actions 등 AI 응답 본문은 로그에 남기지
# 않는다(전체 AI 응답 무조건 로깅 금지).
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
        success = await self._handle_body(message.get("Body"))

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

    async def _handle_body(self, body: str | None) -> bool:
        """SQS 메시지 Body(JSON 문자열)를 파싱하고 Bedrock으로 분석한다.

        Returns:
            처리 성공 여부. False면 호출부가 메시지를 삭제하지 않는다 —
            JSON parsing 실패, GuardDuty 이벤트 구조 오류, Bedrock 호출
            실패, AI 응답 검증 실패를 모두 포함한다(CLIAR-264: Bedrock
            분석까지 성공해야 처리 성공이다).
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

        try:
            analysis = await asyncio.to_thread(analyze_finding, finding)
        except SecurityAnalysisError as exc:
            # 원본 GuardDuty 이벤트나 Bedrock 요청/응답 전문은 로그에
            # 남기지 않는다 — finding_id/finding_type/오류 범주만 남긴다
            # (item 14). 메시지는 삭제하지 않고 기존 재시도/DLQ에 맡긴다.
            logger.warning(
                "guardduty finding bedrock analysis failed",
                extra={
                    "finding_id": finding.finding_id,
                    "finding_type": finding.finding_type,
                    "error_category": type(exc).__name__,
                },
            )
            return False

        finding_fields = finding.model_dump()
        logger.info(
            "guardduty finding analyzed",
            extra={
                **{key: finding_fields[key] for key in _LOGGED_FINDING_FIELDS},
                "risk_level": analysis.risk_level.value,
            },
        )
        return True


# FastAPI lifespan(app/main.py)이 공유하는 단일 인스턴스.
monitoring_worker = MonitoringWorker()
