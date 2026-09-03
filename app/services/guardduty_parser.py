"""GuardDuty EventBridge Finding 이벤트를 내부 스키마로 정규화한다(CLIAR-259).

EventBridge → SQS로 전달되는 이벤트는 AWS get-findings API의 PascalCase
응답이 아니라 EventBridge 이벤트 본문의 camelCase 구조다:

    {
      "source": "aws.guardduty",
      "detail-type": "GuardDuty Finding",
      "detail": {
        "id": "...", "type": "...", "severity": 8,
        "accountId": "...", "region": "...", ...
      }
    }

이 모듈은 AWS API를 호출하지 않는 순수 데이터 변환만 담당한다(SQS
접근은 app/providers/sqs.py).
"""

import json
import logging

from app.schemas.guardduty import GuardDutyFinding

logger = logging.getLogger(__name__)


class GuardDutyEventError(Exception):
    """이벤트 구조 자체가 잘못됐거나(malformed) 핵심 필드가 없는 경우."""


def _extract_sample(service: object) -> bool | None:
    """detail.service.additionalInfo.value에서 sample 플래그를 안전하게 추출한다.

    이 값은 GuardDuty가 dict로 주기도 하고, JSON으로 직렬화된 문자열로
    주기도 한다(예: '{"sample":true,...}'). 부가 정보이므로 파싱에
    실패해도 전체 Finding 처리를 중단시키지 않고 None을 반환한다 —
    핵심 Finding 구조(detail.id/type/severity/accountId/region)가
    malformed인 경우와는 다르게 취급한다.
    """
    if not isinstance(service, dict):
        return None
    additional_info = service.get("additionalInfo")
    if not isinstance(additional_info, dict):
        return None

    value = additional_info.get("value")
    if isinstance(value, dict):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            logger.warning("guardduty additionalInfo.value JSON parse failed")
            return None
    else:
        return None

    if not isinstance(parsed, dict):
        return None
    sample = parsed.get("sample")
    return sample if isinstance(sample, bool) else None


def parse_guardduty_event(event: dict) -> GuardDutyFinding:
    """EventBridge를 통해 전달된 GuardDuty Finding 이벤트를 정규화한다.

    Args:
        event: SQS 메시지 Body를 json.loads한 EventBridge 이벤트 dict.

    Returns:
        정규화된 GuardDutyFinding.

    Raises:
        GuardDutyEventError: event.detail이 없거나 핵심 필드
            (id/type/severity/accountId/region)가 없는 경우. 이 경우
            호출부는 메시지를 삭제하지 않아야 한다(재시도 후 DLQ 이동).
    """
    if not isinstance(event, dict):
        raise GuardDutyEventError("event body is not a JSON object")

    detail = event.get("detail")
    if not isinstance(detail, dict):
        raise GuardDutyEventError("event.detail is missing or not an object")

    try:
        finding_id = detail["id"]
        finding_type = detail["type"]
        severity = detail["severity"]
        account_id = detail["accountId"]
        region = detail["region"]
    except KeyError as exc:
        raise GuardDutyEventError(f"required field missing: {exc}") from exc

    try:
        severity_value = float(severity)
    except (TypeError, ValueError) as exc:
        raise GuardDutyEventError(f"severity is not numeric: {severity!r}") from exc

    resource = detail.get("resource")
    resource_type = resource.get("resourceType") if isinstance(resource, dict) else None

    sample = _extract_sample(detail.get("service"))

    return GuardDutyFinding(
        finding_id=str(finding_id),
        finding_type=str(finding_type),
        severity=severity_value,
        account_id=str(account_id),
        region=str(region),
        title=detail.get("title"),
        description=detail.get("description"),
        created_at=detail.get("createdAt"),
        updated_at=detail.get("updatedAt"),
        resource_type=resource_type,
        sample=sample,
    )
