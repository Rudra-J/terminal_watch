from terminal_bouncer.audit import audit_window


def test_returns_expected_keys():
    result = audit_window([])
    assert "anomaly_score" in result
    assert "flags" in result
    assert "reason" in result

def test_anomaly_score_is_float():
    result = audit_window([])
    assert isinstance(result["anomaly_score"], float)

def test_flags_is_list():
    result = audit_window([])
    assert isinstance(result["flags"], list)

def test_stub_returns_zero_score():
    logs = [{"command": "ls"}, {"command": "pwd"}, {"command": "git status"}]
    result = audit_window(logs)
    assert result["anomaly_score"] == 0.0
    assert result["flags"] == []
