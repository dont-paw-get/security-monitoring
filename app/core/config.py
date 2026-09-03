from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """애플리케이션 기본 환경변수 설정.

    CLIAR-252: security-monitoring 초기 골격. 이 서비스는 자체 DB를
    소유하지 않는다(backend-record가 CLIAR-123 이후 그런 것처럼, 다른
    서비스의 로그/메트릭/트레이스를 관측만 한다) — DATABASE_URL 등
    DB 관련 설정은 두지 않는다.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000

    # 관측(app/core/logging_config.py): stdout -> Grafana Alloy -> Loki.
    # LOG_FORMAT은 "json"(기본, 수집용)과 "text"(로컬 개발용) 중 하나다.
    #
    # 분산 추적 설정(OTEL_SERVICE_NAME / OTEL_EXPORTER_OTLP_ENDPOINT /
    # OTEL_RESOURCE_ATTRIBUTES)은 backend-auth와 동일하게 의도적으로
    # 여기에 두지 않는다. OpenTelemetry SDK가 그 표준 환경변수들을
    # 직접 읽는다(app/core/observability.py). extra="ignore" 덕분에
    # OTEL_* 환경변수가 주입돼도 Settings 생성에는 영향이 없다.
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # CLIAR-252: 실제 탐지 로직이 아직 없는 lifecycle 골격만 존재하므로
    # 기본값은 반드시 비활성(false)이다. 실제 탐지 워커 구현은 이후
    # 별도 티켓에서 이 값을 켜는 시점부터 시작한다(app/services/
    # monitoring_worker.py).
    MONITORING_ENABLED: bool = False


settings = Settings()
