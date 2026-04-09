import re
from typing import Optional


VALID_DECISIONS = {"ALLOW", "DENY", "ASK"}
VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH"}
VAGUE_REASONS = {"seems fine", "looks ok", "ok", "fine", "good", "safe"}


def sanitize_output(raw: str) -> str:
    """Strip markdown code fences and surrounding whitespace."""
    raw = raw.strip()
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"^```\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    return raw.strip()


def validate_output(obj: dict) -> tuple[bool, Optional[str]]:
    """
    Validate LLM output against schema and semantic rules.
    Returns (valid, error_message). error_message is None when valid.
    """
    required = ["decision", "confidence", "risk_level", "reason"]
    for k in required:
        if k not in obj:
            return False, f"Missing required field: {k}"

    if obj["decision"] not in VALID_DECISIONS:
        return False, f"Invalid decision value: {obj['decision']}"

    try:
        conf = float(obj["confidence"])
    except (TypeError, ValueError):
        return False, "confidence must be a number"

    if not (0.0 <= conf <= 1.0):
        return False, f"confidence out of range: {conf}"

    if obj["risk_level"] not in VALID_RISK_LEVELS:
        return False, f"Invalid risk_level value: {obj['risk_level']}"

    reason = str(obj["reason"]).strip()
    if len(reason) < 5:
        return False, f"reason too short (min 5 chars): '{reason}'"

    if reason.lower() in VAGUE_REASONS:
        return False, f"reason is too vague: '{reason}'"

    if obj["decision"] == "ALLOW" and obj["risk_level"] == "HIGH":
        return False, "Inconsistent: decision=ALLOW with risk_level=HIGH"

    return True, None
