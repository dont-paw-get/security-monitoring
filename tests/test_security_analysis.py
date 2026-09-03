"""app/services/security_analysis.py 단위 테스트(CLIAR-264).

실제 AWS Bedrock을 호출하지 않는다 — app.providers.bedrock.invoke_model을
monkeypatch로 대체하거나, analyze_finding(client=...)에 fake boto3 client를
주입한다.
"""

import json

import pytest

from app.providers import bedrock as bedrock_provider
from app.schemas.guardduty import GuardDutyFinding
from app.schemas.security_analysis import RiskLevel
from app.services.security_analysis import (
    SecurityAnalysisError,
    _build_prompt,
    analyze_finding,
    risk_level_from_severity,
)

_FINDING = GuardDutyFinding(
    finding_id="finding-123",
    finding_type="UnauthorizedAccess:EC2/SSHBruteForce",
    severity=8.0,
    account_id="594532711953",
    region="ap-northeast-2",
    title="EC2 instance SSH brute force",
    description="An EC2 instance was involved in SSH brute force attacks.",
    resource_type="Instance",
    sample=False,
)

_VALID_MODEL_JSON = json.dumps(
    {
        "summary": "SSH 무차별 대입 공격이 감지되었습니다.",
        "cause": "외부에서 반복적인 SSH 로그인 시도가 발생했습니다.",
        "impact": "인스턴스가 침해될 경우 내부 네트워크 접근이 가능합니다.",
        "recommended_actions": ["보안 그룹 점검", "SSH 키 교체", "비정상 IP 차단"],
    }
)


def _patch_invoke_model(monkeypatch, text: str | None = None, error: Exception | None = None):
    def fake_invoke_model(prompt, client=None):
        if error is not None:
            raise error
        return text

    monkeypatch.setattr(bedrock_provider, "invoke_model", fake_invoke_model)


# ---------------------------------------------------------------------------
# item 1, 2: 프롬프트 구성 — Finding 필드만 사용하고, 원본 이벤트 전체는
# 포함하지 않는다.
# ---------------------------------------------------------------------------


def test_build_prompt_includes_finding_fields():
    prompt = _build_prompt(_FINDING)

    assert _FINDING.finding_type in prompt
    assert str(_FINDING.severity) in prompt
    assert _FINDING.title in prompt
    assert _FINDING.description in prompt
    assert _FINDING.resource_type in prompt
    assert _FINDING.region in prompt


def test_build_prompt_does_not_include_raw_event_or_sensitive_fields():
    # 원본 EventBridge 이벤트에는 있었지만 GuardDutyFinding에는 존재하지
    # 않는 필드(예: service.additionalInfo 원문, accessKeyId 등)가
    # 프롬프트에 절대 섞여 들어가지 않아야 한다.
    prompt = _build_prompt(_FINDING)

    assert "additionalInfo" not in prompt
    assert "accessKeyId" not in prompt
    assert "detail-type" not in prompt
    assert _FINDING.account_id not in prompt  # account_id는 프롬프트에 포함하지 않는다


# ---------------------------------------------------------------------------
# item 3, 4, 5: 정상 JSON 응답 파싱 + risk_level(결정적 계산) + recommended_actions.
# ---------------------------------------------------------------------------


def test_analyze_finding_parses_valid_json_response(monkeypatch):
    _patch_invoke_model(monkeypatch, text=_VALID_MODEL_JSON)

    result = analyze_finding(_FINDING)

    assert result.summary == "SSH 무차별 대입 공격이 감지되었습니다."
    assert result.cause
    assert result.impact
    assert result.recommended_actions == ["보안 그룹 점검", "SSH 키 교체", "비정상 IP 차단"]


@pytest.mark.parametrize(
    "severity,expected",
    [
        (0.0, RiskLevel.LOW),
        (3.9, RiskLevel.LOW),
        (4.0, RiskLevel.MEDIUM),
        (6.9, RiskLevel.MEDIUM),
        (7.0, RiskLevel.HIGH),
        (8.9, RiskLevel.HIGH),
        (9.0, RiskLevel.CRITICAL),
        (10.0, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_from_severity_boundaries(severity, expected):
    assert risk_level_from_severity(severity) is expected


def test_analyze_finding_risk_level_comes_from_severity_not_model(monkeypatch):
    # 모델 응답에는 risk_level이 아예 없다 — 그래도 severity=8.0(HIGH)로부터
    # 결정적으로 계산되어야 한다.
    _patch_invoke_model(monkeypatch, text=_VALID_MODEL_JSON)

    result = analyze_finding(_FINDING)

    assert result.risk_level is RiskLevel.HIGH


def test_analyze_finding_caps_recommended_actions_to_five(monkeypatch):
    payload = json.loads(_VALID_MODEL_JSON)
    payload["recommended_actions"] = [f"조치{i}" for i in range(10)]
    _patch_invoke_model(monkeypatch, text=json.dumps(payload))

    result = analyze_finding(_FINDING)

    assert len(result.recommended_actions) == 5


# ---------------------------------------------------------------------------
# item 6, 7: malformed JSON / 필수 필드 누락 → 실패.
# ---------------------------------------------------------------------------


def test_analyze_finding_raises_on_malformed_json(monkeypatch):
    _patch_invoke_model(monkeypatch, text="이건 JSON이 아닙니다")

    with pytest.raises(SecurityAnalysisError):
        analyze_finding(_FINDING)


def test_analyze_finding_raises_on_missing_required_field(monkeypatch):
    incomplete = json.dumps({"summary": "요약만 있음"})
    _patch_invoke_model(monkeypatch, text=incomplete)

    with pytest.raises(SecurityAnalysisError):
        analyze_finding(_FINDING)


def test_analyze_finding_raises_on_wrong_type_for_recommended_actions(monkeypatch):
    payload = json.loads(_VALID_MODEL_JSON)
    payload["recommended_actions"] = "이건 리스트가 아니라 문자열입니다"
    _patch_invoke_model(monkeypatch, text=json.dumps(payload))

    with pytest.raises(SecurityAnalysisError):
        analyze_finding(_FINDING)


def test_analyze_finding_strips_code_fence_before_parsing(monkeypatch):
    fenced = f"```json\n{_VALID_MODEL_JSON}\n```"
    _patch_invoke_model(monkeypatch, text=fenced)

    result = analyze_finding(_FINDING)

    assert result.summary == "SSH 무차별 대입 공격이 감지되었습니다."


def test_analyze_finding_raises_when_bedrock_invoke_fails(monkeypatch):
    _patch_invoke_model(monkeypatch, error=bedrock_provider.BedrockInvokeError("boom"))

    with pytest.raises(SecurityAnalysisError):
        analyze_finding(_FINDING)
