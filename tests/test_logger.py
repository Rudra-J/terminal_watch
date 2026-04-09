import json
import os
import pytest
from terminal_bouncer.logger import (
    log_event,
    get_last_n_logs,
    get_or_create_session,
    increment_session_count,
)


@pytest.fixture
def guard_dir(tmp_path):
    return str(tmp_path / ".claude_guard")


def test_log_event_creates_history_file(guard_dir):
    log_event({"command": "ls", "decision": "ALLOW"}, guard_dir)
    assert os.path.exists(os.path.join(guard_dir, "history.jsonl"))

def test_log_event_writes_valid_json(guard_dir):
    log_event({"command": "ls"}, guard_dir)
    with open(os.path.join(guard_dir, "history.jsonl")) as f:
        entry = json.loads(f.readline())
    assert entry["command"] == "ls"

def test_log_event_appends(guard_dir):
    log_event({"command": "ls"}, guard_dir)
    log_event({"command": "pwd"}, guard_dir)
    logs = get_last_n_logs(10, guard_dir)
    assert len(logs) == 2
    assert logs[0]["command"] == "ls"
    assert logs[1]["command"] == "pwd"

def test_get_last_n_returns_most_recent(guard_dir):
    for i in range(5):
        log_event({"command": f"cmd{i}"}, guard_dir)
    logs = get_last_n_logs(3, guard_dir)
    assert len(logs) == 3
    assert logs[0]["command"] == "cmd2"
    assert logs[2]["command"] == "cmd4"

def test_get_last_n_on_empty_dir_returns_empty(guard_dir):
    assert get_last_n_logs(10, guard_dir) == []

def test_session_created_with_correct_fields(guard_dir):
    session = get_or_create_session(guard_dir, "/myrepo")
    assert "session_id" in session
    assert session["repo"] == "/myrepo"
    assert session["total_commands"] == 0
    assert "start_time" in session

def test_session_persisted_across_calls(guard_dir):
    s1 = get_or_create_session(guard_dir, "/repo")
    s2 = get_or_create_session(guard_dir, "/repo")
    assert s1["session_id"] == s2["session_id"]

def test_increment_session_count(guard_dir):
    get_or_create_session(guard_dir, "/repo")
    increment_session_count(guard_dir)
    increment_session_count(guard_dir)
    with open(os.path.join(guard_dir, "session_meta.json")) as f:
        session = json.load(f)
    assert session["total_commands"] == 2
