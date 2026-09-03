"""GuardDuty Finding에 대한 Bedrock AI 분석 결과 스키마(CLIAR-264)."""
from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AIAnalysisContent(BaseModel):
    """Bedrock 모델 응답 JSON을 그대로 검증하는 모델(risk_level 제외).

    risk_level은 모델에게 요청하지 않는다 — GuardDuty severity로부터
    app/services/security_analysis.py의 risk_level_from_severity()가
    결정적으로 계산한다. 이유는 해당 모듈의 docstring 참고.
    """

    summary: str
    cause: str
    impact: str
    recommended_actions: list[str] = Field(default_factory=list)


class SecurityAnalysis(BaseModel):
    """검증 및 risk_level 계산까지 끝난 최종 분석 결과."""

    risk_level: RiskLevel
    summary: str
    cause: str
    impact: str
    recommended_actions: list[str] = Field(default_factory=list)
