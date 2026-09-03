"""
CLIAR-259/264/268/271: GuardDuty SQS Consumer + Bedrock AI 분석 + Discord
Primary/SNS Fallback 관리자 알림(Discord Webhook URL은 AWS Secrets
Manager 또는 로컬 override 환경변수에서 Pod startup 시 1회 조회).

MONITORING_ENABLED=false(기본값, app/core/config.py)면 아무 것도 하지
않는다 — 앱은 워커 없이도 정상 기동/종료된다(boto3/httpx client 생성/AWS
API 호출/polling이 전혀 발생하지 않는다). true이면 GuardDuty SQS 큐를
long polling으로 소비한다:

    receive -> Body JSON parse -> GuardDuty Finding 정규화
    -> Bedrock AI 분석(app/services/security_analysis.py) -> 응답 검증
    -> Discord Webhook 발행 시도(설정된 경우만, app/providers/discord.py)
       -> 성공: SNS는 호출하지 않는다(중복 알림 방지)
       -> 실패 또는 DISCORD_WEBHOOK_URL 미설정: SNS Fallback 발행
          (app/providers/sns.py)
    -> (성공) 구조화 로그 -> DeleteMessage
    -> (실패) 삭제하지 않음 -> VisibilityTimeout 후 재시도
       -> maxReceiveCount(5) 초과 시 큐의 기존 RedrivePolicy가 DLQ로 이동

CLIAR-271 핵심 규칙: Bedrock 분석 성공+검증에 더해, (Discord 성공) 또는
(Discord 실패/미설정 + SNS 성공) 중 하나여야만 "처리 성공"이며, 그때만
DeleteMessage를 호출한다. Discord와 SNS가 모두 실패하면 메시지를
삭제하지 않는다 — 기존 재시도/DLQ 동작을 그대로 따른다. Discord Webhook이
아직 준비되지 않은 환경(DISCORD_WEBHOOK_URL 미설정)에서는 CLIAR-268의
SNS 단독 흐름과 동일하게 동작한다.

이 코드는 DLQ로 직접 SendMessage하지 않는다 — SQS 자체의
RedrivePolicy만 사용한다.
"""

import asyncio
import json
import logging

from app.core.config import settings
from app.providers import discord as discord_provider
from app.providers import secrets_manager as secrets_manager_provider
from app.providers import sns as sns_provider
from app.providers import sqs as sqs_provider
from app.services.alert_message import build_alert, build_discord_payload
from app.services.guardduty_parser import GuardDutyEventError, parse_guardduty_event
from app.services.security_analysis import SecurityAnalysisError, analyze_finding

logger = logging.getLogger(__name__)

# receive_message 자체가 SQS 서버 측에서 최대 WaitTimeSeconds(20초) 동안
# 대기하므로, 정상 흐름(빈 결과 포함)에서는 이 호출 자체가 폴링 주기
# 역할을 한다. 아래 backoff는 receive_message가 예외로 실패했을 때만
# 쓰는 짧은 재시도 대기이며, busy-loop를 막기 위한 것이다.
_ERROR_BACKOFF_SECONDS = 5.0

# 성공 로그에 남길 필드(item 8): finding_id/finding_type/severity/region/
# sample은 Finding에서, risk_level은 분석 결과에서 가져온다. summary/
# cause/impact/recommended_actions/알림 본문 전체는 로그에 남기지 않는다.
_LOGGED_FINDING_FIELDS = ("finding_id", "finding_type", "severity", "region", "sample")


class MonitoringWorker:
    """GuardDuty SQS Consumer의 lifecycle만 관리한다(receive/parse/delete 로직은
    각각 app/providers/sqs.py, app/services/guardduty_parser.py에 위임)."""

    def __init__(self, backoff_seconds: float = _ERROR_BACKOFF_SECONDS) -> None:
        self._backoff_seconds = backoff_seconds
        self._task: asyncio.Task | None = None
        # CLIAR-271 Secrets Manager 연동: Discord Webhook URL은 이 worker
        # 인스턴스 수명 동안 최초 1회만 확인/조회하고 메모리에 캐싱한다
        # (_resolve_discord_webhook_url 참고) — 매 Finding마다 다시
        # 조회하지 않는다.
        self._discord_webhook_url: str | None = None
        self._discord_webhook_resolved = False

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
        if not settings.SNS_ALERT_TOPIC_ARN:
            # CLIAR-268: SNS Publish가 성공해야만 메시지를 삭제하므로, 이
            # 값이 없으면 모든 메시지가 결국 재시도만 반복하다 DLQ로
            # 가버린다 — SQS_GUARDDUTY_QUEUE_URL 누락과 동일하게 아예
            # polling을 시작하지 않는다.
            logger.error(
                "monitoring worker cannot start: SNS_ALERT_TOPIC_ARN is not configured"
            )
            return
        if self._task is not None:
            return

        # CLIAR-271 Secrets Manager 연동: Discord Webhook URL을 Pod
        # startup 시점에 한 번만 확인/조회한다(실패해도 worker 시작을
        # 막지 않는다 — Discord는 선택 채널이고, 실패 시 SNS만으로 계속
        # 동작해야 한다).
        await self._resolve_discord_webhook_url()

        self._task = asyncio.create_task(self._run(), name="monitoring-worker")
        logger.info("monitoring worker started (guardduty sqs consumer)")

    async def _resolve_discord_webhook_url(self) -> str | None:
        """Discord Webhook URL을 최초 1회만 확인/조회하고 메모리에 캐싱한다.

        우선순위(app/core/config.py의 DISCORD_WEBHOOK_URL 주석과 동일):
        1) settings.DISCORD_WEBHOOK_URL이 명시적으로 있으면 그대로 사용
           (로컬 개발/테스트 override용). 2) 없고
           settings.DISCORD_WEBHOOK_SECRET_ID가 있으면 Secrets Manager에서
           조회한다. 3) 둘 다 없거나 조회/값이 실패하면 None을 반환한다 —
           이 경우 이후 모든 Finding은 SNS로만 알림이 간다. Secret 값은
           파일에 저장하지 않고 이 인스턴스의 메모리에만 유지한다.
        """
        if self._discord_webhook_resolved:
            return self._discord_webhook_url

        webhook_url: str | None = None

        if settings.DISCORD_WEBHOOK_URL:
            webhook_url = settings.DISCORD_WEBHOOK_URL
        elif settings.DISCORD_WEBHOOK_SECRET_ID:
            try:
                secret_value = await asyncio.to_thread(
                    secrets_manager_provider.get_secret_value,
                    settings.DISCORD_WEBHOOK_SECRET_ID,
                )
            except secrets_manager_provider.SecretRetrievalError as exc:
                # Secret 값은 로그에 남기지 않는다 — secret_id/오류
                # 범주만 남긴다. Secret 조회 실패는 worker를 죽이지 않고
                # Discord를 비활성화한 채 SNS fallback으로만 동작한다.
                logger.warning(
                    "discord webhook secret retrieval failed, discord disabled (sns fallback only)",
                    extra={
                        "secret_id": settings.DISCORD_WEBHOOK_SECRET_ID,
                        "error_category": type(exc).__name__,
                    },
                )
            else:
                webhook_url = secret_value

        self._discord_webhook_url = webhook_url
        self._discord_webhook_resolved = True
        return webhook_url

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
        """SQS 메시지 Body(JSON 문자열)를 파싱하고 Bedrock 분석 + Discord/SNS 알림까지 수행한다.

        Returns:
            처리 성공 여부. False면 호출부가 메시지를 삭제하지 않는다 —
            JSON parsing 실패, GuardDuty 이벤트 구조 오류, Bedrock 호출
            실패, AI 응답 검증 실패, (Discord 실패/미설정 후) SNS Publish
            실패까지 모두 포함한다(CLIAR-271: Bedrock 분석 성공+검증에
            더해 Discord 또는 SNS 중 하나로 알림 발행까지 성공해야
            처리 성공이다).
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
            # 남기지 않는다 — finding_id/finding_type/오류 범주만 남긴다.
            # Bedrock이 실패하면 SNS는 아예 호출하지 않는다. 메시지는
            # 삭제하지 않고 기존 재시도/DLQ에 맡긴다.
            logger.warning(
                "guardduty finding bedrock analysis failed",
                extra={
                    "finding_id": finding.finding_id,
                    "finding_type": finding.finding_type,
                    "error_category": type(exc).__name__,
                },
            )
            return False

        notification_channel: str | None = None
        sns_message_id: str | None = None

        webhook_url = await self._resolve_discord_webhook_url()
        if webhook_url:
            try:
                discord_payload = build_discord_payload(finding, analysis)
                await asyncio.to_thread(discord_provider.publish_alert, webhook_url, discord_payload)
                notification_channel = "discord"
            except discord_provider.DiscordPublishError as exc:
                # Webhook URL/payload 전체는 로그에 남기지 않는다 —
                # finding_id/finding_type/risk_level/오류 범주만 남긴다.
                # Discord 실패는 워커를 죽이지 않고 SNS fallback으로
                # 넘어간다.
                logger.warning(
                    "discord webhook publish failed, falling back to sns",
                    extra={
                        "finding_id": finding.finding_id,
                        "finding_type": finding.finding_type,
                        "risk_level": analysis.risk_level.value,
                        "error_category": type(exc).__name__,
                    },
                )

        # Discord가 없거나(미설정) 방금 실패한 경우에만 SNS로 fallback한다.
        # Discord가 성공했으면 SNS는 호출하지 않는다(중복 알림 방지).
        if notification_channel is None:
            try:
                subject, message = build_alert(finding, analysis)
                sns_message_id = await asyncio.to_thread(sns_provider.publish_alert, subject, message)
                notification_channel = "sns_fallback"
            except sns_provider.SnsPublishError as exc:
                # 알림 본문 전체/원본 Finding은 로그에 남기지 않는다 —
                # finding_id/finding_type/risk_level/오류 범주만 남긴다.
                # Discord와 SNS가 모두 실패했으므로 메시지는 삭제하지
                # 않고 기존 재시도/DLQ에 맡긴다.
                logger.warning(
                    "security alert sns publish failed",
                    extra={
                        "finding_id": finding.finding_id,
                        "finding_type": finding.finding_type,
                        "risk_level": analysis.risk_level.value,
                        "error_category": type(exc).__name__,
                    },
                )
                return False

        finding_fields = finding.model_dump()
        log_extra = {
            **{key: finding_fields[key] for key in _LOGGED_FINDING_FIELDS},
            "risk_level": analysis.risk_level.value,
            "notification_channel": notification_channel,
        }
        if sns_message_id is not None:
            log_extra["sns_message_id"] = sns_message_id
        logger.info("security alert published", extra=log_extra)
        return True


# FastAPI lifespan(app/main.py)이 공유하는 단일 인스턴스.
monitoring_worker = MonitoringWorker()
