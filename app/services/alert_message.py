"""Bedrock 분석 결과를 관리자용 알림 콘텐츠로 포맷한다(CLIAR-268 SNS,
CLIAR-271 Discord).

GuardDuty 원본 EventBridge 이벤트나 검증되지 않은 데이터를 쓰지 않는다 —
이미 검증된 GuardDutyFinding + SecurityAnalysis(둘 다 app/schemas/)의
필드만 사용한다. Access Key/Token/Credential/service.additionalInfo
원문/원본 Event JSON은 애초에 이 두 스키마에 존재하지 않으므로 알림에도
섞여 들어갈 수 없다.
"""

from app.schemas.guardduty import GuardDutyFinding
from app.schemas.security_analysis import RiskLevel, SecurityAnalysis

# SNS Subject는 최대 100바이트(ASCII)까지만 허용된다. 여유를 두고 자른다.
_SUBJECT_MAX_LENGTH = 100

# Discord embed 필드 제한(https://discord.com/developers/docs/resources/message#embed-object-embed-limits).
# 여기서는 여유를 두고 안전하게 자른다 — Bedrock 결과를 다시 LLM으로
# 줄이지 않고 단순 deterministic truncation만 쓴다.
_DISCORD_TITLE_MAX_LENGTH = 256
_DISCORD_DESCRIPTION_MAX_LENGTH = 2048
_DISCORD_FIELD_VALUE_MAX_LENGTH = 1024
_DISCORD_ACTION_ITEM_MAX_LENGTH = 200

_DISCORD_RISK_COLOR = {
    RiskLevel.LOW: 0x2ECC71,
    RiskLevel.MEDIUM: 0xF1C40F,
    RiskLevel.HIGH: 0xE67E22,
    RiskLevel.CRITICAL: 0xE74C3C,
}


def _truncate(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - 1] + "…"


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


def build_discord_payload(finding: GuardDutyFinding, analysis: SecurityAnalysis) -> dict:
    """Discord Incoming Webhook payload(embed)를 구성한다.

    allowed_mentions.parse=[]로 고정해, Finding title/description 등
    외부에서 흘러들어온 문자열에 @everyone/@here/사용자 멘션이 섞여
    있어도 실제 멘션이 발생하지 않게 한다.
    """
    risk_level = analysis.risk_level.value
    actions = "\n".join(
        f"{i}. {_truncate(action, _DISCORD_ACTION_ITEM_MAX_LENGTH)}"
        for i, action in enumerate(analysis.recommended_actions, start=1)
    ) or "(없음)"

    embed = {
        "title": _truncate(f"[보안 알림] {risk_level} - {finding.finding_type}", _DISCORD_TITLE_MAX_LENGTH),
        "description": _truncate(analysis.summary, _DISCORD_DESCRIPTION_MAX_LENGTH),
        "color": _DISCORD_RISK_COLOR.get(analysis.risk_level, 0x95A5A6),
        "fields": [
            {"name": "Finding ID", "value": _truncate(finding.finding_id, _DISCORD_FIELD_VALUE_MAX_LENGTH), "inline": False},
            {"name": "위험도", "value": risk_level, "inline": True},
            {"name": "심각도", "value": str(finding.severity), "inline": True},
            {"name": "리전", "value": finding.region, "inline": True},
            {"name": "원인", "value": _truncate(analysis.cause, _DISCORD_FIELD_VALUE_MAX_LENGTH), "inline": False},
            {"name": "영향", "value": _truncate(analysis.impact, _DISCORD_FIELD_VALUE_MAX_LENGTH), "inline": False},
            {"name": "권장 대응", "value": _truncate(actions, _DISCORD_FIELD_VALUE_MAX_LENGTH), "inline": False},
            {"name": "Sample", "value": str(finding.sample), "inline": True},
        ],
    }

    return {
        "embeds": [embed],
        "allowed_mentions": {"parse": []},
    }
