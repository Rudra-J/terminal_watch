from terminal_bouncer.decision_engine import decide
from terminal_bouncer.config import Config


def cfg():
    return Config(allow_threshold=0.7, deny_threshold=0.4)


def test_deny_decision_always_blocks():
    result = {"decision": "DENY", "confidence": 0.9, "risk_level": "HIGH", "reason": "dangerous"}
    assert decide(result, cfg()) == "BLOCK"

def test_deny_with_low_confidence_still_blocks():
    result = {"decision": "DENY", "confidence": 0.1, "risk_level": "HIGH", "reason": "dangerous"}
    assert decide(result, cfg()) == "BLOCK"

def test_confidence_at_deny_threshold_blocks():
    result = {"decision": "ALLOW", "confidence": 0.4, "risk_level": "LOW", "reason": "safe"}
    assert decide(result, cfg()) == "BLOCK"

def test_confidence_below_deny_threshold_blocks():
    result = {"decision": "ALLOW", "confidence": 0.2, "risk_level": "LOW", "reason": "safe"}
    assert decide(result, cfg()) == "BLOCK"

def test_allow_above_threshold_executes():
    result = {"decision": "ALLOW", "confidence": 0.9, "risk_level": "LOW", "reason": "safe"}
    assert decide(result, cfg()) == "EXECUTE"

def test_allow_at_threshold_executes():
    result = {"decision": "ALLOW", "confidence": 0.7, "risk_level": "LOW", "reason": "safe"}
    assert decide(result, cfg()) == "EXECUTE"

def test_allow_between_thresholds_asks():
    result = {"decision": "ALLOW", "confidence": 0.55, "risk_level": "LOW", "reason": "probably safe"}
    assert decide(result, cfg()) == "ASK"

def test_ask_decision_asks():
    result = {"decision": "ASK", "confidence": 0.6, "risk_level": "MEDIUM", "reason": "ambiguous"}
    assert decide(result, cfg()) == "ASK"
