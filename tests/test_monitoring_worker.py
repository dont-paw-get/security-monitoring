"""
app/services/monitoring_worker.py 단위 테스트(CLIAR-259: GuardDuty SQS
Consumer, CLIAR-264: Bedrock AI 분석 연동).

실제 AWS를 호출하지 않는다 — app/providers/sqs.py의 receive_messages/
delete_message, app/services/monitoring_worker.analyze_finding을
monkeypatch로 대체한다(backend-record의
monkeypatch.setattr(s3_upload, "upload_scrap_image", ...) 패턴과 동일).
"""

import json

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.providers import sqs as sqs_provider
from app.schemas.security_analysis import RiskLevel, SecurityAnalysis
from app.services import monitoring_worker as monitoring_worker_module
from app.services.monitoring_worker import MonitoringWorker, monitoring_worker
from app.services.security_analysis import SecurityAnalysisError

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


def test_monitoring_enabled_defaults_to_false():
    assert settings.MONITORING_ENABLED is False


def test_app_starts_and_stops_normally_with_worker_disabled(monkeypatch):
    """item 15: MONITORING_ENABLED=false(기본값) 상태에서 lifespan(startup/
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
    """item 15."""
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


async def test_worker_start_creates_task_and_stop_cancels_it_cleanly(monkeypatch):
    """item 14: graceful shutdown."""
    monkeypatch.setattr("app.services.monitoring_worker.settings.MONITORING_ENABLED", True)
    monkeypatch.setattr(
        "app.services.monitoring_worker.settings.SQS_GUARDDUTY_QUEUE_URL",
        "https://sqs.ap-northeast-2.amazonaws.com/594532711953/dpyb-security-monitoring-guardduty-dev",
    )

    monkeypatch.setattr(sqs_provider, "receive_messages", lambda client=None: [])

    worker = MonitoringWorker(backoff_seconds=0.01)

    await worker.start()
    assert worker._task is not None
    assert not worker._task.done()

    await worker.stop()

    assert worker._task is None


# ---------------------------------------------------------------------------
# 메시지 처리 규칙(CLIAR-264): Bedrock 분석까지 성공했을 때만 delete,
# 실패하면(파싱 실패든 Bedrock 실패든) delete하지 않는다.
# ---------------------------------------------------------------------------


async def test_process_message_deletes_on_successful_analysis(monkeypatch):
    """item 10: 성공적인 AI 분석 완료 -> DeleteMessage 호출."""
    deleted = {}

    def fake_delete(receipt_handle, client=None):
        deleted["receipt_handle"] = receipt_handle

    monkeypatch.setattr(sqs_provider, "delete_message", fake_delete)
    _patch_successful_analysis(monkeypatch)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-ok"})

    assert deleted["receipt_handle"] == "r-ok"


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


async def test_process_message_does_not_delete_on_bedrock_aws_error(monkeypatch):
    """item 8: Bedrock AWS 오류(AccessDenied/Throttling 등) -> DeleteMessage 미호출."""
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )

    def raise_bedrock_error(finding, client=None):
        raise SecurityAnalysisError("bedrock invoke failed: AccessDeniedException")

    monkeypatch.setattr(monitoring_worker_module, "analyze_finding", raise_bedrock_error)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-bedrock-error"})

    assert delete_called["value"] is False


async def test_process_message_does_not_delete_on_ai_schema_validation_failure(monkeypatch):
    """item 9: AI 응답이 스키마 검증에 실패 -> DeleteMessage 미호출."""
    delete_called = {"value": False}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda *a, **k: delete_called.__setitem__("value", True)
    )

    def raise_validation_error(finding, client=None):
        raise SecurityAnalysisError("bedrock response failed schema validation: missing 'summary'")

    monkeypatch.setattr(monitoring_worker_module, "analyze_finding", raise_validation_error)

    worker = MonitoringWorker()
    await worker._process_message({"Body": VALID_EVENT_BODY, "ReceiptHandle": "r-schema-error"})

    assert delete_called["value"] is False


async def test_process_message_analyzes_sample_finding_normally(monkeypatch):
    """item 11: sample=true Finding도 정상적으로 Bedrock 분석 및 삭제까지 진행한다."""
    deleted = {}
    monkeypatch.setattr(
        sqs_provider, "delete_message", lambda receipt_handle, client=None: deleted.__setitem__("receipt_handle", receipt_handle)
    )

    captured: dict = {}
    _patch_successful_analysis(monkeypatch, captured=captured)

    worker = MonitoringWorker()
    await worker._process_message({"Body": SAMPLE_EVENT_BODY, "ReceiptHandle": "r-sample"})

    assert captured["finding"].sample is True
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

    worker = MonitoringWorker()
    await worker._run_once()

    assert deleted == ["r-1", "r-2"]


async def test_run_once_survives_receive_error_without_crashing(monkeypatch):
    """item 13: 기존 SQS 수신 오류 테스트 보존."""
    def raise_error(client=None):
        raise RuntimeError("simulated AWS receive_message failure")

    monkeypatch.setattr(sqs_provider, "receive_messages", raise_error)

    worker = MonitoringWorker(backoff_seconds=0.01)
    await worker._run_once()  # 예외가 밖으로 전파되지 않아야 한다(worker crash 방지)


async def test_run_once_survives_bedrock_error_without_crashing(monkeypatch):
    """item 12: Bedrock 오류 1건이 worker 프로세스를 죽이지 않는다."""
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
