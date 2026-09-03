"""app/services/alert_message.py 단위 테스트(CLIAR-268)."""

from app.schemas.guardduty import GuardDutyFinding
from app.schemas.security_analysis import RiskLevel, SecurityAnalysis
from app.services.alert_message import build_alert

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

_ANALYSIS = SecurityAnalysis(
    risk_level=RiskLevel.HIGH,
    summary="SSH 무차별 대입 공격이 감지되었습니다.",
    cause="외부에서 반복적인 SSH 로그인 시도가 발생했습니다.",
    impact="인스턴스가 침해될 경우 내부 네트워크 접근이 가능합니다.",
    recommended_actions=["보안 그룹 점검", "SSH 키 교체", "비정상 IP 차단"],
)


def test_build_alert_includes_required_fields():
    subject, message = build_alert(_FINDING, _ANALYSIS)

    assert "HIGH" in subject
    assert _FINDING.finding_type in subject

    assert _FINDING.finding_type in message
    assert str(_FINDING.severity) in message
    assert _FINDING.region in message
    assert "HIGH" in message
    assert _ANALYSIS.summary in message
    assert _ANALYSIS.cause in message
    assert _ANALYSIS.impact in message
    for action in _ANALYSIS.recommended_actions:
        assert action in message
    assert "False" in message  # Sample: False


def test_build_alert_does_not_include_raw_event_or_credentials():
    subject, message = build_alert(_FINDING, _ANALYSIS)

    for forbidden in ("additionalInfo", "accessKeyId", "detail-type", "AccessKey", "Credential"):
        assert forbidden not in subject
        assert forbidden not in message


def test_build_alert_reflects_sample_flag():
    sample_finding = _FINDING.model_copy(update={"sample": True})

    _, message = build_alert(sample_finding, _ANALYSIS)

    assert "Sample: True" in message


def test_build_alert_caps_subject_length():
    long_type_finding = _FINDING.model_copy(
        update={"finding_type": "A" * 200}
    )

    subject, _ = build_alert(long_type_finding, _ANALYSIS)

    assert len(subject) <= 100
