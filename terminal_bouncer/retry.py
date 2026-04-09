import json
import time
from terminal_bouncer.config import Config
from terminal_bouncer.llm_client import build_prompt, reinforce_prompt, call_llm
from terminal_bouncer.validator import sanitize_output, validate_output


FALLBACK_RESPONSE: dict = {
    "decision": "DENY",
    "confidence": 0.0,
    "risk_level": "HIGH",
    "reason": "LLM output invalid after retries",
}


def evaluate_command(
    command: str, config: Config
) -> tuple[dict, list[str], bool]:
    """
    Evaluate command via LLM with retry.
    Returns (result, raw_responses, fallback_used).
    """
    prompt = build_prompt(command)
    raw_responses: list[str] = []

    for attempt in range(config.max_retries):
        if attempt > 0:
            time.sleep(2 ** (attempt - 1))  # 1s, 2s for attempts 1 and 2

        raw = ""
        try:
            raw = call_llm(prompt, config)
            raw_responses.append(raw)
            sanitized = sanitize_output(raw)
            parsed = json.loads(sanitized)
            valid, _ = validate_output(parsed)
            if valid:
                return parsed, raw_responses, False
            else:
                prompt = reinforce_prompt(prompt, raw)
        except Exception:
            prompt = reinforce_prompt(prompt, raw)

    return FALLBACK_RESPONSE, raw_responses, True
