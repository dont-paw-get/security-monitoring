"""
app/services/monitoring_worker.py 단위 테스트(CLIAR-259: GuardDuty SQS
Consumer, CLIAR-264: Bedrock AI 분석 연동, CLIAR-268: SNS 관리자 알림
연동, CLIAR-271: Discord Primary/SNS Fallback 연동).

실제 AWS/Discord를 호출하지 않는다 — app/providers/sqs.py의
receive_messages/delete_message, app/services/monitoring_worker의
analyze_finding, sns_provider.publish_alert, discord_provider.publish_alert를
monkeypatch로 대체한다(backend-record의
monkeypatch.setattr(s3_upload, "upload_scrap_image", ...) 패턴과 동일).
"""

import json
import logging

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.providers import discord as discord_provider
from app.providers import sns as sns_provider
from app.providers import sqs as sqs_provider
from app.schemas.security_analysis import RiskLevel, SecurityAnalysis
from app.services import monitoring_worker as monitoring_worker_module
from app.services.monitoring_worker import MonitoringWorker, monitoring_worker
from app.services.security_analysis import SecurityAnalysisError

SNS_ALERT_TOPIC_ARN = "arn:aws:sns:ap-northeast-2:594532711953:dpyb-security-monitoring-alerts-dev"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1111111111/secret-token-should-not-be-logged"

VALID_EVENT_BODY = json.dumps(
    {
        "source": "aws.guardduty",
        "detail-type": "GuardDuty Finding",
        "detail": {
            "id": "finding-123",
            "type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "severity": 8,
            "accountId": "594532711953",
            "region": "ap-northeast-2",
        },
    }
)

SAMPLE_EVENT_BODY = json.dumps(
    {
        "source": "aws.guardduty",
        "detail-type": "GuardDuty Finding",
        "detail": {
            "id": "finding-sample",
            "type": "Recon:EC2/PortProbeUnprotectedPort",
            "severity": 5,
            "accountId": "594532711953",
            "region": "ap-northeast-2",
            "service": {"additionalInfo": {"value": '{"sample":true}'}},
        },
    }
)


def _fake_analysis(risk_level: RiskLevel = RiskLevel.HIGH) -> SecurityAnalysis:
    return SecurityAnalysis(
        risk_level=risk_level,
        summary="테스트 요약",
        cause="테스트 원인",
        impact="테스트 영향",
        recommended_actions=["조치1", "조치2"],
    )


def _patch_successful_analysis(monkeypatch, captured: dict | None = None):
    def fake_analyze_finding(finding, client=None):
        if captured is not None:
            captured["finding"] = finding
        return _fake_analysis()

    monkeypatch.setattr(monitoring_worker_module, "analyze_finding", fake_analyze_finding)


def _patch_successful_sns_publish(monkeypatch, captured: dict | None = None, message_id: str = "sns-msg-1"):
    def fake_publish_alert(subject, message, client=None):
        if captured is not None:
            captured["subject"] = subject
            captured["message"] = message
        return message_id

    monkeypatch.setattr(sns_provider, "publish_alert", fake_publish_alert)


def _patch_successful_discord_publish(monkeypatch, captured: dict | None = None):
    def fake_publish_alert(payload, client=None):
        if captured is not None:
            captured["payload"] = payload
        return None

    monkeypatch.setattr(discord_provider, "publish_alert", fake_publish_alert)


def _patch_failing_discord_publish(monkeypatch, message: str = "Discord webhook returned HTTP 500"):
    def raise_discord_error(payload, client=None):
        raise discord_provider.DiscordPublishError(message)

    monkeypatch.setattr(discord_provider, "publish_alert", raise_discord_error)


def _patch_failing_sns_publish(monkeypatch, message: str = "SNS publish failed: AccessDeniedException"):
    def raise_sns_error(subject, message_, client=None):
        raise sns_provider.SnsPublishError(message)

    monkeypatch.setattr(sns_provider, "publish_alert", raise_sns_error)


def test_monitoring_enabled_defaults_to_false():
    assert settings.MONITORING_ENABLED is False


def test_discord_webhook_url_defaults_to_none():
    assert settings.DISCORD_WEBHOOK_URL is None


def test_app_starts_and_stops_normally_with_worker_disabled(monkeypatch):
    """item 16: MONITORING_ENABLED=false(기본값) 상태에서 lifespan(startup/
    shutdown)이 예외 없이 정상적으로 열리고 닫히는지 확인한다. AWS 호출이
    전혀 없어야 하므로 receive_messages를 감시해 호출되지 않았음을
    확인한다."""
    called = {"value": False}

    def fail_if_called(client=None):
        called["value"] = True
        return []

    monkeypatch.setattr(sqs_provider, "receive_messages", fail_if_called)

    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200

    assert monitoring_worker._task is None
    assert called["value"] is False  # AWS polling이 전혀 발생하지 않았어야 한다


async def test_worker_start_is_noop_when_disabled(monkeypatch):
    """item 16."""
    worker = MonitoringWorker()
    monkeypatch.setattr("app.services.monitoring_worker.settings.MONITORING_ENABLED", False)

    await worker.start()

    assert worker._task is None
    await worker.stop()  # 아무 것도 취소할 게 없어도 예외 없이 반환되어야 한다


async def test_worker_does_not_start_when_queue_url_missing(monkeypatch):
    """MONITORING_ENABLED=true여도 SQS_GUARDDUTY_QUEUE_URL이 없으면 시작하지 않는다."""
    worker = MonitoringWorker()
    monkeypatch.setattr("app.services.monitoring_worker.settings.MONITORING_ENABLED", True)
    monkeypatch.setattr("app.services.monitoring_worker.settings.SQS_GUARDDUTY_QUEUE_URL", None)

    await worker.start()

    assert worker._task is None


async def test_worker_does_not_start_when_sns_topic_arn_missing(monkeypatch):
    """SNS_ALERT_TOPIC_ARN은 여전히 필수다(Discord 없이도 SNS fallback이
    동작해야 하므로) — 없으면 시작하지 않는다."""
    worker = MonitoringWorker()
    monkeypatch.setattr("app.services.monitoring_worker.settings.MONITORING_ENABLED", True)
    monkeypatch.setattr(
        "app.services.monitoring_worker.settings.SQS_GUARDDUTY_QUEUE_URL",
        "https://sqs.ap-northeast-2.amazonaws.com/594532711953/dpyb-security-monitoring-guardduty-dev",
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.SNS_ALERT_TOPIC_ARN", None)

    await worker.start()

    assert worker._task is None


async def test_worker_starts_without_discord_webhook_configured(monkeypatch):
    """CLIAR-271: DISCORD_WEBHOOK_URL이 없어도(현재 DEV 기본 상태) worker는
    정상적으로 시작한다 — Discord는 필수가 아니다."""
    monkeypatch.setattr("app.services.monitoring_worker.settings.MONITORING_ENABLED", True)
    monkeypatch.setattr(
        "app.services.monitoring_worker.settings.SQS_GUARDDUTY_QUEUE_URL",
        "https://sqs.ap-northeast-2.amazonaws.com/594532711953/dpyb-security-monitoring-guardduty-dev",
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.SNS_ALERT_TOPIC_ARN", SNS_ALERT_TOPIC_ARN)
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", None)
    monkeypatch.setattr(sqs_provider, "receive_messages", lambda client=None: [])

    worker = MonitoringWorker(backoff_seconds=0.01)
    await worker.start()
    assert worker._task is not None
    await worker.stop()


async def test_worker_start_creates_task_and_stop_cancels_it_cleanly(monkeypatch):
    """item 15: graceful shutdown."""
    monkeypatch.setattr("app.services.monitoring_worker.settings.MONITORING_ENABLED", True)
    monkeypatch.setattr(
        "app.services.monitoring_worker.settings.SQS_GUARDDUTY_QUEUE_URL",
        "https://sqs.ap-northeast-2.amazonaws.com/594532711953/dpyb-security-monitoring-guardduty-dev",
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.SNS_ALERT_TOPIC_ARN", SNS_ALERT_TOPIC_ARN)

    monkeypatch.setattr(sqs_provider, "receive_messages", lambda client=None: [])

    worker = MonitoringWorker(backoff_seconds=0.01)

    await worker.start()
    assert worker._task is not None
    assert not worker._task.done()

    await worker.stop()

    assert worker._task is None


# ---------------------------------------------------------------------------
# 알림 정책(CLIAR-271): Discord Primary -> 실패/미설정 시 SNS Fallback.
# 어느 한쪽이든 성공해야 DeleteMessage, 둘 다 실패하면 삭제하지 않는다.
# ---------------------------------------------------------------------------


async def test_discord_success_deletes_message_and_does_not_call_sns(monkeypatch):
    """item 1, 9: Discord 성공 -> SNS 미호출 -> DeleteMessage 호출(중복 알림 없음)."""
    deleted = {}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.__setitem__("receipt_handle", receipt_handle)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    _patch_successful_analysis(monkeypatch)
    _patch_successful_discord_publish(monkeypatch)

    sns_called = {"value": False}
    monkeypatch.setattr(
        sns_provider, "publish_alert", lambda *a, **k: sns_called.__setitem__("value", True)
    )

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-discord-ok"})

    assert sns_called["value"] is False
    assert deleted["receipt_handle"] == "r-discord-ok"


async def test_discord_failure_falls_back_to_sns_and_deletes_on_success(monkeypatch):
    """item 2: Discord 실패 -> SNS 호출 -> SNS 성공 -> DeleteMessage 호출."""
    deleted = {}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.__setitem__("receipt_handle", receipt_handle)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    _patch_successful_analysis(monkeypatch)
    _patch_failing_discord_publish(monkeypatch)
    sns_captured: dict = {}
    _patch_successful_sns_publish(monkeypatch, captured=sns_captured)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-fallback-ok"})

    assert "message" in sns_captured
    assert deleted["receipt_handle"] == "r-fallback-ok"


async def test_discord_failure_and_sns_failure_does_not_delete(monkeypatch):
    """item 3: Discord 실패 + SNS 실패 -> DeleteMessage 미호출."""
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    _patch_successful_analysis(monkeypatch)
    _patch_failing_discord_publish(monkeypatch)
    _patch_failing_sns_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-both-fail"})

    assert delete_called["value"] is False


async def test_discord_unset_skips_discord_and_uses_sns(monkeypatch):
    """item 4: Discord 미설정 -> Discord 미호출 -> SNS 호출 -> 성공 -> DeleteMessage 호출."""
    deleted = {}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.__setitem__("receipt_handle", receipt_handle)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", None)
    _patch_successful_analysis(monkeypatch)

    discord_called = {"value": False}
    monkeypatch.setattr(
        discord_provider, "publish_alert", lambda *a, **k: discord_called.__setitem__("value", True)
    )
    _patch_successful_sns_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-no-webhook"})

    assert discord_called["value"] is False
    assert deleted["receipt_handle"] == "r-no-webhook"


async def test_discord_unset_and_sns_failure_does_not_delete(monkeypatch):
    """item 5: Webhook 미설정 + SNS 실패 -> DeleteMessage 미호출."""
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", None)
    _patch_successful_analysis(monkeypatch)
    _patch_failing_sns_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-no-webhook-sns-fail"})

    assert delete_called["value"] is False


async def test_discord_429_falls_back_to_sns_without_crashing(monkeypatch):
    """item 6: Discord 429(rate limit) -> worker crash 없음 -> SNS fallback."""
    deleted = {}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.__setitem__("receipt_handle", receipt_handle)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    _patch_successful_analysis(monkeypatch)
    _patch_failing_discord_publish(monkeypatch, message="Discord webhook returned HTTP 429")
    _patch_successful_sns_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-429"})  # 예외 없이 반환되어야 한다

    assert deleted["receipt_handle"] == "r-429"


async def test_discord_5xx_falls_back_to_sns(monkeypatch):
    """item 7: Discord 5xx -> SNS fallback."""
    deleted = {}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.__setitem__("receipt_handle", receipt_handle)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    _patch_successful_analysis(monkeypatch)
    _patch_failing_discord_publish(monkeypatch, message="Discord webhook returned HTTP 503")
    _patch_successful_sns_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-5xx"})

    assert deleted["receipt_handle"] == "r-5xx"


async def test_discord_timeout_falls_back_to_sns(monkeypatch):
    """item 8: Discord timeout -> SNS fallback."""
    deleted = {}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.__setitem__("receipt_handle", receipt_handle)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    _patch_successful_analysis(monkeypatch)
    _patch_failing_discord_publish(monkeypatch, message="Discord webhook request failed: TimeoutException")
    _patch_successful_sns_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-timeout"})

    assert deleted["receipt_handle"] == "r-timeout"


async def test_discord_payload_sets_allowed_mentions_and_omits_raw_event(monkeypatch):
    """item 10, 11: Discord로 전달되는 payload에 allowed_mentions.parse=[]가
    있고, 원본 GuardDuty Event 전체가 포함되지 않는다."""
    monkeypatch.setattr(sqs_provider, "delete_message", lambda *a, **k: None)
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    _patch_successful_analysis(monkeypatch)
    captured: dict = {}
    _patch_successful_discord_publish(monkeypatch, captured=captured)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-payload-check"})

    payload = captured["payload"]
    assert payload["allowed_mentions"] == {"parse": []}
    serialized = str(payload)
    for forbidden in ("detail-type", "aws.guardduty", "accountId", "AccessKey"):
        assert forbidden not in serialized


async def test_discord_failure_does_not_log_webhook_url(monkeypatch, caplog):
    """item 12: Discord 실패 로그에도 Webhook URL이 노출되지 않는다."""
    monkeypatch.setattr(sqs_provider, "delete_message", lambda *a, **k: None)
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    _patch_successful_analysis(monkeypatch)
    _patch_failing_discord_publish(monkeypatch)
    _patch_successful_sns_publish(monkeypatch)

    worker = MonitoringWorker()
    with caplog.at_level(logging.WARNING):
        await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-log-check"})

    for record in caplog.records:
        assert DISCORD_WEBHOOK_URL not in record.getMessage()
        for value in record.__dict__.values():
            assert DISCORD_WEBHOOK_URL not in str(value)


async def test_sample_finding_processed_normally_with_discord_configured(monkeypatch):
    """item 13: sample=true Finding도 Discord/SNS 정책이 동일하게 적용된다(skip 없음)."""
    deleted = {}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.__setitem__("receipt_handle", receipt_handle)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    captured_finding: dict = {}
    _patch_successful_analysis(monkeypatch, captured=captured_finding)
    _patch_successful_discord_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._process_message({"Body": SAMPLE_EVENT_BODY, "ReceiptHandle": "r-sample"})

    assert captured_finding["finding"].sample is True
    assert deleted["receipt_handle"] == "r-sample"


async def test_process_message_does_not_delete_when_body_is_malformed_json(monkeypatch):
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )

    worker = MonitoringWorker()
    await worker._process_message({"Body": "{not valid json", "ReceiptHandle": "r-bad-json"})

    assert delete_called["value"] is False


async def test_process_message_does_not_delete_when_guardduty_event_is_malformed(monkeypatch):
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )

    worker = MonitoringWorker()
    # detail이 아예 없는 malformed GuardDuty 이벤트.
    body = json.dumps({"source": "aws.guardduty", "detail-type": "GuardDuty Finding"})
    await worker._process_message({"Body": body, "ReceiptHandle": "r-bad-finding"})

    assert delete_called["value"] is False


async def test_process_message_does_not_delete_on_bedrock_error_and_calls_neither_channel(monkeypatch):
    """item 14: Bedrock 실패 -> Discord/SNS 모두 미호출 -> DeleteMessage 미호출."""
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)

    def raise_bedrock_error(finding, client=None):
        raise SecurityAnalysisError("bedrock invoke failed: AccessDeniedException")

    monkeypatch.setattr(monitoring_worker_module, "analyze_finding", raise_bedrock_error)

    discord_called = {"value": False}
    monkeypatch.setattr(
        discord_provider, "publish_alert", lambda *a, **k: discord_called.__setitem__("value", True)
    )
    sns_called = {"value": False}
    monkeypatch.setattr(
        sns_provider, "publish_alert", lambda *a, **k: sns_called.__setitem__("value", True)
    )

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-bedrock-error"})

    assert discord_called["value"] is False
    assert sns_called["value"] is False
    assert delete_called["value"] is False


# ---------------------------------------------------------------------------
# _run_once: 수신 결과 처리 + 예외 상황에서도 worker가 죽지 않는지.
# ---------------------------------------------------------------------------


async def test_run_once_handles_empty_receive_result(monkeypatch):
    monkeypatch.setattr(sqs_provider, "receive_messages", lambda client=None: [])

    worker = MonitoringWorker()
    await worker._run_once()  # 예외 없이 반환되어야 한다


async def test_run_once_processes_all_received_messages(monkeypatch):
    deleted = []
    monkeypatch.setattr(
        sqs_provider,
        "receive_messages",
        lambda client=None: [
            {"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-1"},
            {"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-2"},
        ],
    )
    monkeypatch.setattr(sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.append(receipt_handle))
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", None)
    _patch_successful_analysis(monkeypatch)
    _patch_successful_sns_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._run_once()

    assert deleted == ["r-1", "r-2"]


async def test_run_once_survives_receive_error_without_crashing(monkeypatch):
    """기존 SQS 수신 오류 테스트 보존."""
    def raise_error(client=None):
        raise RuntimeError("simulated AWS receive_message failure")

    monkeypatch.setattr(sqs_provider, "receive_messages", raise_error)

    worker = MonitoringWorker(backoff_seconds=0.01)
    await worker._run_once()  # 예외가 밖으로 전파되지 않아야 한다(worker crash 방지)


async def test_run_once_survives_bedrock_error_without_crashing(monkeypatch):
    monkeypatch.setattr(
        sqs_provider,
        "receive_messages",
        lambda client=None: [{"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-crash-check"}],
    )
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )

    def raise_bedrock_error(finding, client=None):
        raise SecurityAnalysisError("bedrock invoke failed: ThrottlingException")

    monkeypatch.setattr(monitoring_worker_module, "analyze_finding", raise_bedrock_error)

    worker = MonitoringWorker(backoff_seconds=0.01)
    await worker._run_once()  # 예외가 밖으로 전파되지 않아야 한다

    assert delete_called["value"] is False


async def test_run_once_survives_discord_and_sns_error_without_crashing(monkeypatch):
    """Discord/SNS 둘 다 실패하는 극단적인 경우에도 _run_once 레벨에서 worker가 죽지 않는다."""
    monkeypatch.setattr(
        sqs_provider,
        "receive_messages",
        lambda client=None: [{"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-both-crash-check"}],
    )
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.DISCORD_WEBHOOK_URL", DISCORD_WEBHOOK_URL)
    _patch_successful_analysis(monkeypatch)
    _patch_failing_discord_publish(monkeypatch)
    _patch_failing_sns_publish(monkeypatch)

    worker = MonitoringWorker(backoff_seconds=0.01)
    await worker._run_once()  # 예외가 밖으로 전파되지 않아야 한다

    assert delete_called["value"] is False
