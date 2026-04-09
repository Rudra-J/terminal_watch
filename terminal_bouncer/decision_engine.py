from terminal_bouncer.config import Config


def decide(result: dict, config: Config) -> str:
    """Map LLM result to final action: 'EXECUTE', 'BLOCK', or 'ASK'."""
    if result["decision"] == "DENY":
        return "BLOCK"

    if result["confidence"] <= config.deny_threshold:
        return "BLOCK"

    if result["decision"] == "ALLOW" and result["confidence"] >= config.allow_threshold:
        return "EXECUTE"

    return "ASK"
