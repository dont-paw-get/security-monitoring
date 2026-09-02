"""
Prometheus HTTP 메트릭(app/core/metrics.py, app/api/metrics.py) 최소 검증.

CLIAR-252 범위: /metrics가 정상 노출되는지, Micrometer 호환 시계열
이름(http_server_requests_seconds_*)을 쓰는지만 확인한다. 라벨/카디널리티
세부 검증은 실제 라우트가 늘어나는 후속 티켓에서 backend-auth의
tests/test_metrics.py 수준으로 확장한다.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

METRIC = "http_server_requests_seconds"


def test_metrics_endpoint_is_reachable():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]


def test_exposes_micrometer_compatible_series():
    # 존재하지 않는 경로를 하나 호출해 최소 한 개의 샘플을 만든다.
    client.get("/this-route-does-not-exist")
    body = client.get("/metrics").text
    assert f"{METRIC}_count" in body
    assert f"{METRIC}_bucket" in body
    assert f"{METRIC}_sum" in body


def test_health_and_metrics_paths_are_excluded_from_aggregation():
    client.get("/health")
    body = client.get("/metrics").text
    assert 'uri="/health"' not in body
    assert 'uri="/metrics"' not in body
