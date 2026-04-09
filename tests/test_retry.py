import json
from unittest.mock import patch
from terminal_bouncer.retry import evaluate_command, FALLBACK_RESPONSE
from terminal_bouncer.config import Config


VALID_RAW = json.dumps({
    "decision": "ALLOW",
    "confidence": 0.9,
    "risk_level": "LOW",
    "reason": "safe read operation",
})

INVALID_RAW = "not json at all"


def cfg():
    return Config(max_retries=3)


def test_returns_valid_result_on_first_attempt():
    with patch("terminal_bouncer.retry.call_llm", return_value=VALID_RAW):
        result, raws, fallback = evaluate_command("ls", cfg())
    assert result["decision"] == "ALLOW"
    assert fallback is False
    assert len(raws) == 1


def test_returns_valid_result_after_two_bad_attempts():
    responses = [INVALID_RAW, INVALID_RAW, VALID_RAW]
    with patch("terminal_bouncer.retry.call_llm", side_effect=responses), \
         patch("terminal_bouncer.retry.time.sleep"):
        result, raws, fallback = evaluate_command("ls", cfg())
    assert result["decision"] == "ALLOW"
    assert fallback is False
    assert len(raws) == 3


def test_returns_fallback_after_all_retries_exhausted():
    with patch("terminal_bouncer.retry.call_llm", return_value=INVALID_RAW), \
         patch("terminal_bouncer.retry.time.sleep"):
        result, raws, fallback = evaluate_command("ls", cfg())
    assert result == FALLBACK_RESPONSE
    assert fallback is True
    assert len(raws) == 3


def test_returns_fallback_on_llm_exception():
    with patch("terminal_bouncer.retry.call_llm", side_effect=Exception("timeout")), \
         patch("terminal_bouncer.retry.time.sleep"):
        result, raws, fallback = evaluate_command("ls", cfg())
    assert result == FALLBACK_RESPONSE
    assert fallback is True


def test_exponential_backoff_sleeps():
    sleep_calls = []
    with patch("terminal_bouncer.retry.call_llm", return_value=INVALID_RAW), \
         patch("terminal_bouncer.retry.time.sleep", side_effect=lambda s: sleep_calls.append(s)):
        evaluate_command("ls", cfg())
    # attempt 0: no sleep; attempt 1: sleep 1; attempt 2: sleep 2
    assert sleep_calls == [1, 2]


def test_fallback_response_structure():
    assert FALLBACK_RESPONSE["decision"] == "DENY"
    assert FALLBACK_RESPONSE["confidence"] == 0.0
    assert FALLBACK_RESPONSE["risk_level"] == "HIGH"
    assert len(FALLBACK_RESPONSE["reason"]) >= 5
