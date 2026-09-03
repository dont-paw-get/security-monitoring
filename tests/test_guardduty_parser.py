"""app/services/guardduty_parser.py 단위 테스트(CLIAR-259).

실제 AWS를 호출하지 않는다 — EventBridge를 통해 전달되는 GuardDuty
Finding 이벤트(camelCase) dict를 직접 만들어 파싱만 검증한다.
"""

import pytest

from app.services.guardduty_parser import GuardDutyEventError, parse_guardduty_event


def _event(**detail_overrides):
    detail = {
        "id": "finding-123",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": 8,
        "accountId": "594532711953",
        "region": "ap-northeast-2",
        "title": "SSH brute force detected",
        "description": "example description",
        "createdAt": "2026-09-01T00:00:00Z",
        "updatedAt": "2026-09-01T00:00:01Z",
        "resource": {"resourceType": "Instance"},
        **detail_overrides,
    }
    return {
        "source": "aws.guardduty",
        "detail-type": "GuardDuty Finding",
        "detail": detail,
    }


def test_parses_normal_guardduty_event():
    finding = parse_guardduty_event(_event())

    assert finding.finding_id == "finding-123"
    assert finding.finding_type == "UnauthorizedAccess:EC2/SSHBruteForce"
    assert finding.severity == 8.0
    assert finding.account_id == "594532711953"
    assert finding.region == "ap-northeast-2"


def test_maps_camelcase_fields_correctly():
    finding = parse_guardduty_event(_event())

    assert finding.title == "SSH brute force detected"
    assert finding.description == "example description"
    assert finding.created_at == "2026-09-01T00:00:00Z"
    assert finding.updated_at == "2026-09-01T00:00:01Z"
    assert finding.resource_type == "Instance"


def test_extracts_core_identity_fields():
    finding = parse_guardduty_event(
        _event(id="abc", type="Recon:EC2/PortProbeUnprotectedPort", severity=4, accountId="111122223333", region="us-east-1")
    )

    assert (finding.finding_id, finding.finding_type, finding.severity, finding.account_id, finding.region) == (
        "abc",
        "Recon:EC2/PortProbeUnprotectedPort",
        4.0,
        "111122223333",
        "us-east-1",
    )


def test_extracts_sample_true_from_json_string_additional_info():
    event = _event(service={"additionalInfo": {"value": '{"sample":true,"threatListName":"x"}'}})

    finding = parse_guardduty_event(event)

    assert finding.sample is True


def test_extracts_sample_from_dict_additional_info():
    event = _event(service={"additionalInfo": {"value": {"sample": False}}})

    finding = parse_guardduty_event(event)

    assert finding.sample is False


def test_malformed_additional_info_value_does_not_fail_whole_parse():
    event = _event(service={"additionalInfo": {"value": "{not valid json"}})

    finding = parse_guardduty_event(event)

    assert finding.sample is None
    assert finding.finding_id == "finding-123"  # 핵심 필드는 정상 파싱됨


def test_missing_additional_info_results_in_sample_none():
    event = _event(service={})

    finding = parse_guardduty_event(event)

    assert finding.sample is None


def test_missing_detail_raises_guardduty_event_error():
    with pytest.raises(GuardDutyEventError):
        parse_guardduty_event({"source": "aws.guardduty", "detail-type": "GuardDuty Finding"})


def test_missing_required_field_raises_guardduty_event_error():
    event = _event()
    del event["detail"]["severity"]

    with pytest.raises(GuardDutyEventError):
        parse_guardduty_event(event)


def test_non_numeric_severity_raises_guardduty_event_error():
    event = _event(severity="not-a-number")

    with pytest.raises(GuardDutyEventError):
        parse_guardduty_event(event)


def test_non_dict_event_raises_guardduty_event_error():
    with pytest.raises(GuardDutyEventError):
        parse_guardduty_event("not a dict")
