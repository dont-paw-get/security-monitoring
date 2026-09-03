"""GuardDuty Finding을 Bedrock으로 분석하는 오케스트레이션(CLIAR-264).

흐름: GuardDutyFinding -> 프롬프트 구성(최소 필드만) -> Bedrock Converse
-> 응답 JSON 파싱/검증 -> risk_level은 severity로 결정적으로 계산 ->
SecurityAnalysis.

risk_level 정책(작업 지시 item 11에서 위임된 설계 결정):
GuardDuty의 공식 severity 점수(0~10, 이미 AWS가 산정한 신뢰 가능한
신호)로부터 이 모듈이 결정적으로(risk_level_from_severity) 계산한다.
LLM에게 risk_level 자체를 맡기지 않는다 — 프롬프트에서도 요청하지
않는다(AIAnalysisContent에 risk_level 필드가 없다). 이유:

  1. 예측 가능성 — 같은 severity는 항상 같은 risk_level이어야 한다.
     LLM 출력은 모델 버전/프롬프트 해석에 따라 흔들릴 수 있다.
  2. 보안 — Finding의 title/description 등은 결국 외부(공격자가 만든
     리소스 이름 등)에서 흘러들어올 수 있는 문자열이다. risk_level
     계산을 LLM에서 완전히 제외하면, "이 Finding은 위험하지 않다"고
     LLM이 설득/오판되게 만드는 공격 표면 자체가 사라진다.
  3. GuardDuty severity는 이미 AWS가 계산한 신뢰 가능한 신호이므로,
     LLM은 그 위에 설명/권고만 얹는 보조 역할로 충분하다.

즉 이 시스템은 "위험도 판단은 결정적 코드, 설명/권고는 LLM"으로
역할을 분리한다 — 작업 지시가 요구한 "더 예측 가능한 설계"를
우선한 결과다.
"""

import json
import logging

from pydantic import ValidationError

from app.providers import bedrock as bedrock_provider
from app.schemas.guardduty import GuardDutyFinding
from app.schemas.security_analysis import AIAnalysisContent, RiskLevel, SecurityAnalysis

logger = logging.getLogger(__name__)

_MAX_RECOMMENDED_ACTIONS = 5

_PROMPT_TEMPLATE = """당신은 AWS GuardDuty Finding을 설명하는 보안 분석 보조자입니다.
아래 Finding 정보를 바탕으로 반드시 한국어로 분석하세요.

역할과 제약:
- 당신은 설명과 권고만 제공합니다. 어떤 조치도 직접 실행하지 않습니다.
- 반드시 아래 JSON 형식으로만 응답하세요. 코드 블록(```)이나 그 외
  설명 문장을 추가하지 마세요.
- recommended_actions는 최대 5개까지, 각 항목은 한 문장으로 간결하게
  작성하세요.

Finding 정보:
- 유형: {finding_type}
- GuardDuty 심각도(0~10): {severity}
- 제목: {title}
- 설명: {description}
- 리소스 유형: {resource_type}
- 리전: {region}
- 샘플(테스트) Finding 여부: {sample}

응답 형식(JSON만):
{{
  "summary": "핵심 내용을 2~3문장으로 요약",
  "cause": "발생 원인 설명",
  "impact": "잠재적 영향 설명",
  "recommended_actions": ["권고 조치 1", "권고 조치 2"]
}}"""


class SecurityAnalysisError(Exception):
    """Bedrock 호출 실패 또는 AI 응답 검증 실패.

    호출부(app/services/monitoring_worker.py)는 이 예외를 받으면 SQS
    메시지를 삭제하지 않아야 한다.
    """


def _build_prompt(finding: GuardDutyFinding) -> str:
    """Bedrock에 전달할 프롬프트를 구성한다.

    원본 GuardDuty EventBridge 이벤트 전체나 service.additionalInfo 원문을
    넣지 않고, 보안 분석에 필요한 최소 필드만 사용한다.
    """
    return _PROMPT_TEMPLATE.format(
        finding_type=finding.finding_type,
        severity=finding.severity,
        title=finding.title or "(제공되지 않음)",
        description=finding.description or "(제공되지 않음)",
        resource_type=finding.resource_type or "(제공되지 않음)",
        region=finding.region,
        sample=finding.sample,
    )


def _strip_code_fence(text: str) -> str:
    """모델이 지시를 어기고 코드 블록으로 감싸 응답한 경우를 대비한 방어적 처리."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        first_newline = cleaned.find("\n")
        cleaned = cleaned[first_newline + 1:] if first_newline != -1 else ""
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
    return cleaned.strip()


def risk_level_from_severity(severity: float) -> RiskLevel:
    """GuardDuty severity(0~10)를 고정 구간으로 risk_level에 매핑한다.

    모듈 docstring 참고: LLM 출력이 아니라 이 함수가 risk_level의 유일한
    출처다. 구간: [0,4)=LOW, [4,7)=MEDIUM, [7,9)=HIGH, [9,10]=CRITICAL.
    """
    if severity < 4:
        return RiskLevel.LOW
    if severity < 7:
        return RiskLevel.MEDIUM
    if severity < 9:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def analyze_finding(finding: GuardDutyFinding, client=None) -> SecurityAnalysis:
    """GuardDuty Finding을 Bedrock으로 분석하고 검증된 결과를 반환한다.

    boto3 호출은 동기이므로 이 함수 자체도 동기다 — 호출부가
    asyncio.to_thread로 감싼다(app/services/monitoring_worker.py).

    Raises:
        SecurityAnalysisError: Bedrock 호출 실패, 응답이 JSON이 아니거나
            필수 필드가 없거나 타입이 맞지 않는 경우.
    """
    prompt = _build_prompt(finding)

    try:
        raw_text = bedrock_provider.invoke_model(prompt, client=client)
    except bedrock_provider.BedrockInvokeError as exc:
        raise SecurityAnalysisError(f"bedrock invoke failed: {exc}") from exc

    cleaned = _strip_code_fence(raw_text)

    try:
        payload = json.loads(cleaned)
    except (TypeError, ValueError) as exc:
        raise SecurityAnalysisError("bedrock response is not valid JSON") from exc

    try:
        content = AIAnalysisContent.model_validate(payload)
    except ValidationError as exc:
        raise SecurityAnalysisError(f"bedrock response failed schema validation: {exc}") from exc

    return SecurityAnalysis(
        risk_level=risk_level_from_severity(finding.severity),
        summary=content.summary,
        cause=content.cause,
        impact=content.impact,
        recommended_actions=content.recommended_actions[:_MAX_RECOMMENDED_ACTIONS],
    )
