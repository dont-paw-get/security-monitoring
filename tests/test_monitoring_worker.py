"""
app/services/monitoring_worker.py 단위 테스트(CLIAR-259: GuardDuty SQS Consumer).

실제 AWS를 호출하지 않는다 — app/providers/sqs.py의 receive_messages/
delete_message를 monkeypatch로 대체한다(backend-record의
monkeypatch.setattr(s3_upload, "upload_scrap_image", ...) 패턴과 동일).
"""

import json

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.providers import sqs as sqs_provider
from app.services.monitoring_worker import MonitoringWorker, monitoring_worker

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


def test_monitoring_enabled_defaults_to_false():
    assert settings.MONITORING_ENABLED is False


def test_app_starts_and_stops_normally_with_worker_disabled(monkeypatch):
    """MONITORING_ENABLED=false(기본값) 상태에서 lifespan(startup/shutdown)이
    예외 없이 정상적으로 열리고 닫히는지 확인한다. AWS 호출이 전혀
    없어야 하므로 receive_messages를 감시해 호출되지 않았음을 확인한다."""
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
# 메시지 처리 규칙: 성공했을 때만 delete, 실패하면 delete하지 않는다.
# ---------------------------------------------------------------------------


async def test_process_message_deletes_on_success(monkeypatch):
    deleted = {}

    def fake_delete(receipt_handle, client=None):
        deleted["receipt_handle"] = receipt_handle

    monkeypatch.setattr(sqs_provider, "delete_message", fake_delete)

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

    worker = MonitoringWorker()
    await worker._run_once()

    assert deleted == ["r-1", "r-2"]


async def test_run_once_survives_receive_error_without_crashing(monkeypatch):
    def raise_error(client=None):
        raise RuntimeError("simulated AWS receive_message failure")

    monkeypatch.setattr(sqs_provider, "receive_messages", raise_error)

    worker = MonitoringWorker(backoff_seconds=0.01)
    await worker._run_once()  # 예외가 밖으로 전파되지 않아야 한다(worker crash 방지)
