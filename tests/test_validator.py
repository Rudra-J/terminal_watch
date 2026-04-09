from terminal_bouncer.validator import sanitize_output, validate_output


# --- sanitize_output ---

def test_strips_json_markdown_fence():
    raw = "```json\n{\"a\": 1}\n```"
    assert sanitize_output(raw) == '{"a": 1}'

def test_strips_plain_markdown_fence():
    raw = "```\n{\"a\": 1}\n```"
    assert sanitize_output(raw) == '{"a": 1}'

def test_strips_surrounding_whitespace():
    assert sanitize_output("  hello  ") == "hello"

def test_passthrough_clean_json():
    raw = '{"decision": "ALLOW"}'
    assert sanitize_output(raw) == raw


# --- validate_output ---

def test_valid_allow_low():
    obj = {"decision": "ALLOW", "confidence": 0.9, "risk_level": "LOW", "reason": "safe command"}
    valid, err = validate_output(obj)
    assert valid is True
    assert err is None

def test_valid_deny_high():
    obj = {"decision": "DENY", "confidence": 0.95, "risk_level": "HIGH", "reason": "deletes system files"}
    valid, err = validate_output(obj)
    assert valid is True

def test_valid_ask_medium():
    obj = {"decision": "ASK", "confidence": 0.5, "risk_level": "MEDIUM", "reason": "ambiguous intent"}
    valid, err = validate_output(obj)
    assert valid is True

def test_missing_field_decision():
    obj = {"confidence": 0.9, "risk_level": "LOW", "reason": "fine"}
    valid, err = validate_output(obj)
    assert valid is False
    assert "decision" in err

def test_missing_field_reason():
    obj = {"decision": "ALLOW", "confidence": 0.9, "risk_level": "LOW"}
    valid, err = validate_output(obj)
    assert valid is False
    assert "reason" in err

def test_invalid_decision_value():
    obj = {"decision": "MAYBE", "confidence": 0.9, "risk_level": "LOW", "reason": "not sure at all"}
    valid, err = validate_output(obj)
    assert valid is False
    assert "decision" in err

def test_confidence_above_1():
    obj = {"decision": "ALLOW", "confidence": 1.5, "risk_level": "LOW", "reason": "safe command"}
    valid, err = validate_output(obj)
    assert valid is False
    assert "confidence" in err

def test_confidence_below_0():
    obj = {"decision": "DENY", "confidence": -0.1, "risk_level": "HIGH", "reason": "very dangerous"}
    valid, err = validate_output(obj)
    assert valid is False

def test_invalid_risk_level():
    obj = {"decision": "ALLOW", "confidence": 0.9, "risk_level": "CRITICAL", "reason": "safe command"}
    valid, err = validate_output(obj)
    assert valid is False
    assert "risk_level" in err

def test_reason_too_short():
    obj = {"decision": "ALLOW", "confidence": 0.9, "risk_level": "LOW", "reason": "ok"}
    valid, err = validate_output(obj)
    assert valid is False
    assert "reason" in err

def test_vague_reason_rejected():
    obj = {"decision": "ALLOW", "confidence": 0.9, "risk_level": "LOW", "reason": "seems fine"}
    valid, err = validate_output(obj)
    assert valid is False
    assert "vague" in err

def test_allow_high_risk_inconsistency():
    obj = {"decision": "ALLOW", "confidence": 0.9, "risk_level": "HIGH", "reason": "trust me it is fine"}
    valid, err = validate_output(obj)
    assert valid is False
    assert "Inconsistent" in err
