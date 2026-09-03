"""
app/services/monitoring_worker.py 단위 테스트(CLIAR-259: GuardDuty SQS
Consumer, CLIAR-264: Bedrock AI 분석 연동, CLIAR-268: SNS 관리자 알림 연동).

실제 AWS를 호출하지 않는다 — app/providers/sqs.py의 receive_messages/
delete_message, app/services/monitoring_worker.analyze_finding,
app/services/monitoring_worker.sns_provider.publish_alert를 monkeypatch로
대체한다(backend-record의
monkeypatch.setattr(s3_upload, "upload_scrap_image", ...) 패턴과 동일).
"""

import json

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.providers import sns as sns_provider
from app.providers import sqs as sqs_provider
from app.schemas.security_analysis import RiskLevel, SecurityAnalysis
from app.services import monitoring_worker as monitoring_worker_module
from app.services.monitoring_worker import MonitoringWorker, monitoring_worker
from app.services.security_analysis import SecurityAnalysisError

SNS_ALERT_TOPIC_ARN = "arn:aws:sns:ap-northeast-2:594532711953:dpyb-security-monitoring-alerts-dev"

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


def _patch_successful_publish(monkeypatch, captured: dict | None = None, message_id: str = "sns-msg-1"):
    def fake_publish_alert(subject, message, client=None):
        if captured is not None:
            captured["subject"] = subject
            captured["message"] = message
        return message_id

    monkeypatch.setattr(sns_provider, "publish_alert", fake_publish_alert)


def test_monitoring_enabled_defaults_to_false():
    assert settings.MONITORING_ENABLED is False


def test_app_starts_and_stops_normally_with_worker_disabled(monkeypatch):
    """item 13: MONITORING_ENABLED=false(기본값) 상태에서 lifespan(startup/
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
    """item 13."""
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
    """CLIAR-268: MONITORING_ENABLED=true + SQS_GUARDDUTY_QUEUE_URL이 있어도
    SNS_ALERT_TOPIC_ARN이 없으면 시작하지 않는다(SNS Publish 없이는
    메시지를 삭제할 수 없어 모든 메시지가 결국 DLQ로 가버리는 상황을
    막기 위함)."""
    worker = MonitoringWorker()
    monkeypatch.setattr("app.services.monitoring_worker.settings.MONITORING_ENABLED", True)
    monkeypatch.setattr(
        "app.services.monitoring_worker.settings.SQS_GUARDDUTY_QUEUE_URL",
        "https://sqs.ap-northeast-2.amazonaws.com/594532711953/dpyb-security-monitoring-guardduty-dev",
    )
    monkeypatch.setattr("app.services.monitoring_worker.settings.SNS_ALERT_TOPIC_ARN", None)

    await worker.start()

    assert worker._task is None


async def test_worker_start_creates_task_and_stop_cancels_it_cleanly(monkeypatch):
    """item 12: graceful shutdown."""
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
# 메시지 처리 규칙(CLIAR-268): Bedrock 분석 + SNS Publish까지 성공했을
# 때만 delete, 실패하면(파싱/Bedrock/SNS 무엇이든) delete하지 않는다.
# ---------------------------------------------------------------------------


async def test_process_message_deletes_on_successful_analysis_and_publish(monkeypatch):
    """item 4: 정상 SNS Publish 후 DeleteMessage."""
    deleted = {}

    def fake_delete(receipt_handle, client=None):
        deleted["receipt_handle"] = receipt_handle

    monkeypatch.setattr(sqs_provider, "delete_message", fake_delete)
    _patch_successful_analysis(monkeypatch)
    _patch_successful_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-ok"})

    assert deleted["receipt_handle"] == "r-ok"


async def test_process_message_calls_sns_publish_with_expected_fields(monkeypatch):
    """item 1, 2: 정상 Analysis 완료 -> SNS Publish 호출 + 알림에 필요한 필드 포함."""
    monkeypatch.setattr(sqs_provider, "delete_message", lambda *a, **k: None)
    _patch_successful_analysis(monkeypatch)
    captured: dict = {}
    _patch_successful_publish(monkeypatch, captured=captured)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-fields"})

    assert "HIGH" in captured["subject"]
    message = captured["message"]
    assert "UnauthorizedAccess:EC2/SSHBruteForce" in message
    assert "테스트 요약" in message
    assert "조치1" in message
    assert "8.0" in message


async def test_process_message_does_not_send_raw_guardduty_event_to_sns(monkeypatch):
    """item 3: 원본 GuardDuty 전체 Event가 SNS 알림에 포함되지 않는다."""
    monkeypatch.setattr(sqs_provider, "delete_message", lambda *a, **k: None)
    _patch_successful_analysis(monkeypatch)
    captured: dict = {}
    _patch_successful_publish(monkeypatch, captured=captured)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-no-raw"})

    for forbidden in ("detail-type", "aws.guardduty", "accountId", "AccessKey"):
        assert forbidden not in captured["subject"]
        assert forbidden not in captured["message"]


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


async def test_process_message_does_not_delete_on_bedrock_error_and_does_not_call_sns(monkeypatch):
    """item 6, 7: Bedrock 실패 -> SNS 미호출 + DeleteMessage 미호출."""
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )

    def raise_bedrock_error(finding, client=None):
        raise SecurityAnalysisError("bedrock invoke failed: AccessDeniedException")

    monkeypatch.setattr(monitoring_worker_module, "analyze_finding", raise_bedrock_error)

    sns_called = {"value": False}
    monkeypatch.setattr(
        sns_provider, "publish_alert", lambda *a, **k: sns_called.__setitem__("value", True)
    )

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-bedrock-error"})

    assert sns_called["value"] is False
    assert delete_called["value"] is False


async def test_process_message_does_not_delete_when_sns_publish_fails(monkeypatch):
    """item 5: SNS Publish 실패 -> DeleteMessage 미호출."""
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )
    _patch_successful_analysis(monkeypatch)

    def raise_sns_error(subject, message, client=None):
        raise sns_provider.SnsPublishError("SNS publish failed: AccessDeniedException")

    monkeypatch.setattr(sns_provider, "publish_alert", raise_sns_error)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-sns-error"})

    assert delete_called["value"] is False


async def test_process_message_does_not_crash_on_sns_access_denied(monkeypatch):
    """item 8: SNS AccessDenied에서도 worker crash 안 함(_process_message가 예외 없이 반환)."""
    monkeypatch.setattr(sqs_provider, "delete_message", lambda *a, **k: None)
    _patch_successful_analysis(monkeypatch)

    def raise_access_denied(subject, message, client=None):
        raise sns_provider.SnsPublishError("SNS publish failed: AccessDeniedException")

    monkeypatch.setattr(sns_provider, "publish_alert", raise_access_denied)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-crash-check"})  # 예외 없이 반환되어야 한다


async def test_process_message_does_not_delete_on_kms_related_error(monkeypatch):
    """item 9: KMS 관련 AWS 오류(KMSAccessDenied 등)에서도 DeleteMessage 안 함."""
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )
    _patch_successful_analysis(monkeypatch)

    def raise_kms_error(subject, message, client=None):
        raise sns_provider.SnsPublishError("SNS publish failed: KMSAccessDeniedException")

    monkeypatch.setattr(sns_provider, "publish_alert", raise_kms_error)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-kms-error"})

    assert delete_called["value"] is False


async def test_process_message_publishes_sample_finding_normally(monkeypatch):
    """item 10: sample=true Finding도 정상적으로 SNS Publish 및 삭제까지 진행한다(skip 금지)."""
    deleted = {}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.__setitem__("receipt_handle", receipt_handle)
    )

    captured_finding: dict = {}
    _patch_successful_analysis(monkeypatch, captured=captured_finding)
    captured_publish: dict = {}
    _patch_successful_publish(monkeypatch, captured=captured_publish)

    worker = MonitoringWorker()
    await worker._process_message({"Body": SAMPLE_EVENT_BODY, "ReceiptHandle": "r-sample"})

    assert captured_finding["finding"].sample is True
    assert "Sample: True" in captured_publish["message"]
    assert deleted["receipt_handle"] == "r-sample"


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
    _patch_successful_analysis(monkeypatch)
    _patch_successful_publish(monkeypatch)

    worker = MonitoringWorker()
    await worker._run_once()

    assert deleted == ["r-1", "r-2"]


async def test_run_once_survives_receive_error_without_crashing(monkeypatch):
    """item 11(구 item 13): 기존 SQS 수신 오류 테스트 보존."""
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


async def test_run_once_survives_sns_error_without_crashing(monkeypatch):
    """item 8 연장: SNS 오류 1건이 _run_once 레벨에서도 worker를 죽이지 않는다."""
    monkeypatch.setattr(
        sqs_provider,
        "receive_messages",
        lambda client=None: [{"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-sns-crash-check"}],
    )
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )
    _patch_successful_analysis(monkeypatch)

    def raise_sns_error(subject, message, client=None):
        raise sns_provider.SnsPublishError("SNS publish failed: ThrottlingException")

    monkeypatch.setattr(sns_provider, "publish_alert", raise_sns_error)

    worker = MonitoringWorker(backoff_seconds=0.01)
    await worker._run_once()  # 예외가 밖으로 전파되지 않아야 한다

    assert delete_called["value"] is False
