"""
app/services/monitoring_worker.py 최소 검증(CLIAR-252: lifecycle 골격만).

실제 AWS/외부 API를 호출하지 않는다. 탐지 로직 자체는 아직 없으므로
여기서는 "꺼져 있어도 앱이 정상 기동/종료되는지"와 "켜졌을 때 태스크가
정상적으로 생성/취소되는지"만 확인한다.
"""

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.services.monitoring_worker import MonitoringWorker, monitoring_worker


def test_monitoring_enabled_defaults_to_false():
    assert settings.MONITORING_ENABLED is False


def test_app_starts_and_stops_normally_with_worker_disabled():
    """MONITORING_ENABLED=false(기본값) 상태에서 lifespan(startup/shutdown)이
    예외 없이 정상적으로 열리고 닫히는지 확인한다."""
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
    # with 블록을 빠져나오며 shutdown(lifespan 종료)까지 예외 없이 완료됨.
    assert monitoring_worker._task is None


async def test_worker_start_is_noop_when_disabled(monkeypatch):
    worker = MonitoringWorker()
    monkeypatch.setattr(
        "app.services.monitoring_worker.settings.MONITORING_ENABLED", False
    )

    await worker.start()

    assert worker._task is None
    await worker.stop()  # 아무 것도 취소할 게 없어도 예외 없이 반환되어야 한다


async def test_worker_start_creates_task_and_stop_cancels_it_cleanly(monkeypatch):
    monkeypatch.setattr(
        "app.services.monitoring_worker.settings.MONITORING_ENABLED", True
    )
    # 실제 주기(60s)를 기다리지 않도록 매우 짧은 interval을 쓴다.
    worker = MonitoringWorker(interval_seconds=0.01)

    await worker.start()
    assert worker._task is not None
    assert not worker._task.done()

    await worker.stop()

    assert worker._task is None
