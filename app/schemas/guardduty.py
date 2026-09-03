"""GuardDuty Finding의 정규화된 내부 표현(CLIAR-259).

EventBridge를 통해 전달되는 AWS 원본 이벤트(camelCase, 부가 필드 다수)를
애플리케이션 전체에 그대로 퍼뜨리지 않고, 이후 단계(Bedrock 분석 등)에서도
재사용할 수 있는 최소 보안 필드만 정규화해서 담는다.
"""

from pydantic import BaseModel


class GuardDutyFinding(BaseModel):
    finding_id: str
    finding_type: str
    severity: float
    account_id: str
    region: str
    title: str | None = None
    description: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    resource_type: str | None = None
    # GuardDuty 샘플(테스트용) Finding 여부. detail.service.additionalInfo.value에서
    # 안전하게 추출한다(app/services/guardduty_parser.py) — 추출 실패 시 None.
    sample: bool | None = None
