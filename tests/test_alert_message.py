"""app/services/alert_message.py 단위 테스트(CLIAR-268)."""

from app.schemas.guardduty import GuardDutyFinding
from app.schemas.security_analysis import RiskLevel, SecurityAnalysis
from app.services.alert_message import build_alert, build_discord_payload

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


# ---------------------------------------------------------------------------
# build_discord_payload (CLIAR-271)
# ---------------------------------------------------------------------------


def test_build_discord_payload_includes_required_fields():
    payload = build_discord_payload(_FINDING, _ANALYSIS)

    embed = payload["embeds"][0]
    assert "HIGH" in embed["title"]
    assert _FINDING.finding_type in embed["title"]
    assert embed["description"] == _ANALYSIS.summary

    field_values = {field["name"]: field["value"] for field in embed["fields"]}
    assert field_values["Finding ID"] == _FINDING.finding_id
    assert field_values["위험도"] == "HIGH"
    assert field_values["심각도"] == str(_FINDING.severity)
    assert field_values["리전"] == _FINDING.region
    assert field_values["원인"] == _ANALYSIS.cause
    assert field_values["영향"] == _ANALYSIS.impact
    for action in _ANALYSIS.recommended_actions:
        assert action in field_values["권장 대응"]
    assert field_values["Sample"] == "False"


def test_build_discord_payload_sets_allowed_mentions_parse_empty():
    payload = build_discord_payload(_FINDING, _ANALYSIS)

    assert payload["allowed_mentions"] == {"parse": []}


def test_build_discord_payload_allowed_mentions_survives_mention_like_content():
    # title/description에 @everyone 등이 섞여 있어도 allowed_mentions는
    # 항상 고정된 빈 parse 리스트여야 한다(payload 구조만으로도 실제
    # 멘션이 발동하지 않도록 강제).
    finding_with_mention_text = _FINDING.model_copy(
        update={"title": "@everyone please look at this", "description": "<@123456789> ping"}
    )

    payload = build_discord_payload(finding_with_mention_text, _ANALYSIS)

    assert payload["allowed_mentions"] == {"parse": []}


def test_build_discord_payload_does_not_include_raw_event_or_credentials():
    payload = build_discord_payload(_FINDING, _ANALYSIS)
    serialized = str(payload)

    for forbidden in ("additionalInfo", "accessKeyId", "detail-type", "AccessKey", "Credential"):
        assert forbidden not in serialized


def test_build_discord_payload_truncates_long_fields_without_extra_llm_call():
    long_analysis = SecurityAnalysis(
        risk_level=RiskLevel.CRITICAL,
        summary="가" * 5000,
        cause="나" * 5000,
        impact="다" * 5000,
        recommended_actions=["라" * 500],
    )

    payload = build_discord_payload(_FINDING, long_analysis)

    embed = payload["embeds"][0]
    assert len(embed["description"]) <= 2048
    field_values = {field["name"]: field["value"] for field in embed["fields"]}
    assert len(field_values["원인"]) <= 1024
    assert len(field_values["영향"]) <= 1024
    assert len(field_values["권장 대응"]) <= 1024


def test_build_discord_payload_reflects_sample_flag():
    sample_finding = _FINDING.model_copy(update={"sample": True})

    payload = build_discord_payload(sample_finding, _ANALYSIS)

    field_values = {field["name"]: field["value"] for field in payload["embeds"][0]["fields"]}
    assert field_values["Sample"] == "True"
