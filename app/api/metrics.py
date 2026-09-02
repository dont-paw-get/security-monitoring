from fastapi import APIRouter, Response

from app.core.metrics import metrics_exposition

router = APIRouter()


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics():
    """
    Prometheus 스크레이핑 엔드포인트.

    dev overlay의 ServiceMonitor(`k8s/overlays/dev/servicemonitor.yaml`)가
    이 경로를 스크레이핑한다. 클러스터 내부(Prometheus)에서만 호출된다.
    """
    body, content_type = metrics_exposition()
    return Response(content=body, media_type=content_type)
