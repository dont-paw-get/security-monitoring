"""Bedrock 분석 결과를 관리자용 SNS 알림 텍스트로 포맷한다(CLIAR-268).

GuardDuty 원본 EventBridge 이벤트나 검증되지 않은 데이터를 쓰지 않는다 —
이미 검증된 GuardDutyFinding + SecurityAnalysis(둘 다 app/schemas/)의
필드만 사용한다. Access Key/Token/Credential/service.additionalInfo
원문/원본 Event JSON은 애초에 이 두 스키마에 존재하지 않으므로 알림에도
섞여 들어갈 수 없다.
"""

from app.schemas.guardduty import GuardDutyFinding
from app.schemas.security_analysis import SecurityAnalysis

# SNS Subject는 최대 100바이트(ASCII)까지만 허용된다. 여유를 두고 자른다.
_SUBJECT_MAX_LENGTH = 100


def build_alert(finding: GuardDutyFinding, analysis: SecurityAnalysis) -> tuple[str, str]:
    """(subject, message) 튜플을 반환한다."""
    risk_level = analysis.risk_level.value
    subject = f"[보안 알림] {risk_level} - {finding.finding_type}"
    if len(subject) > _SUBJECT_MAX_LENGTH:
        subject = subject[: _SUBJECT_MAX_LENGTH - 1] + "…"

    actions = "\n".join(
        f"{i}. {action}" for i, action in enumerate(analysis.recommended_actions, start=1)
    )

    message = (
        f"[보안 알림] {risk_level} - {finding.finding_type}\n\n"
        f"Finding ID: {finding.finding_id}\n"
        f"위험도: {risk_level}\n"
        f"심각도: {finding.severity}\n"
        f"리전: {finding.region}\n\n"
        f"요약: {analysis.summary}\n"
        f"원인: {analysis.cause}\n"
        f"영향: {analysis.impact}\n\n"
        f"권장 대응:\n{actions}\n\n"
        f"Sample: {finding.sample}"
    )
    return subject, message
