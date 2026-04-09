import json
from unittest.mock import patch
import pytest
from terminal_bouncer.guard import guard_command
from terminal_bouncer.config import Config
from terminal_bouncer.retry import FALLBACK_RESPONSE


def _safe_llm():
    return (
        {"decision": "ALLOW", "confidence": 0.9, "risk_level": "LOW", "reason": "safe command"},
        ["raw_response"],
        False,
    )


def _deny_llm():
    return (
        {"decision": "DENY", "confidence": 0.95, "risk_level": "HIGH", "reason": "deletes system files"},
        ["raw_response"],
        False,
    )


def _fallback_llm():
    return (FALLBACK_RESPONSE, [], True)


@pytest.fixture
def config():
    return Config()


def test_rule_engine_blocks_immediately(config, tmp_path):
    result = guard_command("rm -rf /", config=config, cwd=str(tmp_path))
    assert result["final_action"] == "BLOCK"
    assert result["log"]["rule_triggered"] is True


def test_llm_allow_executes_command(config, tmp_path):
    with patch("terminal_bouncer.guard.evaluate_command", return_value=_safe_llm()), \
         patch("terminal_bouncer.guard.execute_command", return_value=(0, "output\n", "")):
        result = guard_command("git status", config=config, cwd=str(tmp_path))
    assert result["final_action"] == "EXECUTE"
    assert result["executed"] is True
    assert result["stdout"] == "output\n"


def test_llm_deny_blocks_command(config, tmp_path):
    with patch("terminal_bouncer.guard.evaluate_command", return_value=_deny_llm()):
        result = guard_command("rm dangerous.sh", config=config, cwd=str(tmp_path))
    assert result["final_action"] == "BLOCK"
    assert result["executed"] is False


def test_fallback_asks_user(config, tmp_path):
    with patch("terminal_bouncer.guard.evaluate_command", return_value=_fallback_llm()):
        result = guard_command("some command", config=config, cwd=str(tmp_path))
    assert result["final_action"] == "ASK"
    assert result["log"]["fallback_used"] is True
    assert result["executed"] is False


def test_log_entry_has_required_fields(config, tmp_path):
    with patch("terminal_bouncer.guard.evaluate_command", return_value=_safe_llm()), \
         patch("terminal_bouncer.guard.execute_command", return_value=(0, "", "")):
        result = guard_command("git status", config=config, cwd=str(tmp_path))
    log = result["log"]
    for field in ("timestamp", "session_id", "command", "command_hash",
                  "classification", "llm_decision", "confidence", "risk_level",
                  "final_action", "executed", "reason", "rule_triggered",
                  "fallback_used", "latency_ms", "cwd", "attempts"):
        assert field in log, f"Missing log field: {field}"


def test_log_classification_correct(config, tmp_path):
    with patch("terminal_bouncer.guard.evaluate_command", return_value=_safe_llm()), \
         patch("terminal_bouncer.guard.execute_command", return_value=(0, "", "")):
        result = guard_command("git status", config=config, cwd=str(tmp_path))
    assert result["log"]["classification"] == "GIT"


def test_history_written_to_disk(config, tmp_path):
    with patch("terminal_bouncer.guard.evaluate_command", return_value=_safe_llm()), \
         patch("terminal_bouncer.guard.execute_command", return_value=(0, "", "")):
        guard_command("git status", config=config, cwd=str(tmp_path))
    log_path = tmp_path / ".claude_guard" / "history.jsonl"
    assert log_path.exists()
    with open(log_path) as f:
        entry = json.loads(f.readline())
    assert entry["command"] == "git status"
