"""
CLIAR-252: 실제 탐지 로직 없이 lifecycle 골격만 제공하는 모니터링 워커.

MONITORING_ENABLED=false(기본값, app/core/config.py)면 아무 것도 하지
않는다 — 앱은 워커 없이도 정상 기동/종료된다. 이후 실제 탐지 규칙
(예: 로그인 실패 반복, OCR 비정상 호출 탐지)을 구현하는 티켓에서는
_run_once()의 본문만 채우면 된다. startup/shutdown 연동, 정상 취소,
busy-loop 방지는 이미 갖춰져 있다.

CLIAR-252 범위 밖(아직 하지 않음): Loki/Tempo/Prometheus 조회, AWS
호출, Slack/email 알림 전송, 실제 탐지 규칙 실행. asyncio 표준 라이브러리
외에 Celery/APScheduler 같은 추가 스케줄러 라이브러리도 쓰지 않는다.
"""

import asyncio
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

# 실제 탐지 규칙이 없는 지금은 의미 없는 값이다. 첫 탐지 규칙을 추가할
# 때 규칙에 맞는 주기로 조정한다.
_DEFAULT_INTERVAL_SECONDS = 60.0


class MonitoringWorker:
    """asyncio 기반 백그라운드 루프의 lifecycle만 관리한다(탐지 로직 없음)."""

    def __init__(self, interval_seconds: float = _DEFAULT_INTERVAL_SECONDS) -> None:
        self._interval_seconds = interval_seconds
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """MONITORING_ENABLED가 false면 아무 것도 하지 않는다."""
        if not settings.MONITORING_ENABLED:
            logger.info("monitoring worker disabled (MONITORING_ENABLED=false)")
            return
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name="monitoring-worker")
        logger.info(
            "monitoring worker started (interval_seconds=%.0f)",
            self._interval_seconds,
        )

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
        """매 반복 asyncio.sleep으로 이벤트 루프에 양보한다(busy-loop 금지)."""
        try:
            while True:
                await self._run_once()
                await asyncio.sleep(self._interval_seconds)
        except asyncio.CancelledError:
            raise

    async def _run_once(self) -> None:
        """탐지 규칙 실행 지점 — CLIAR-252에서는 의도적으로 비워 둔다.

        여기서 외부 API/AWS를 호출하지 않는다. Loki/Tempo/Prometheus
        조회나 알림 전송 같은 실제 탐지 로직은 이후 별도 티켓에서
        구현한다.
        """
        logger.debug("monitoring worker tick (no-op)")


# FastAPI lifespan(app/main.py)이 공유하는 단일 인스턴스.
monitoring_worker = MonitoringWorker()
