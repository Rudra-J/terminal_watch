import json
import os
import uuid
from datetime import datetime, timezone


def _ensure_dir(guard_dir: str) -> None:
    os.makedirs(guard_dir, exist_ok=True)


def log_event(entry: dict, guard_dir: str) -> None:
    """Append one log entry to history.jsonl."""
    _ensure_dir(guard_dir)
    log_path = os.path.join(guard_dir, "history.jsonl")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def get_last_n_logs(n: int, guard_dir: str) -> list[dict]:
    """Return the last n log entries from history.jsonl."""
    log_path = os.path.join(guard_dir, "history.jsonl")
    if not os.path.exists(log_path):
        return []
    entries: list[dict] = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries[-n:]


def get_or_create_session(guard_dir: str, repo_path: str) -> dict:
    """Load existing session or create a new one."""
    _ensure_dir(guard_dir)
    session_path = os.path.join(guard_dir, "session_meta.json")
    if os.path.exists(session_path):
        with open(session_path, encoding="utf-8") as f:
            return json.load(f)
    session = {
        "session_id": str(uuid.uuid4()),
        "start_time": datetime.now(timezone.utc).isoformat(),
        "repo": repo_path,
        "total_commands": 0,
    }
    _write_session(session, session_path)
    return session


def increment_session_count(guard_dir: str) -> None:
    """Increment total_commands counter in session_meta.json."""
    session_path = os.path.join(guard_dir, "session_meta.json")
    if not os.path.exists(session_path):
        return
    with open(session_path, encoding="utf-8") as f:
        session = json.load(f)
    session["total_commands"] += 1
    _write_session(session, session_path)


def _write_session(session: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2)
