import os
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional

from terminal_bouncer.config import Config
from terminal_bouncer.rule_engine import check_rules
from terminal_bouncer.classifier import classify_command
from terminal_bouncer.hasher import hash_command
from terminal_bouncer.retry import evaluate_command, FALLBACK_RESPONSE
from terminal_bouncer.decision_engine import decide
from terminal_bouncer.logger import log_event, get_or_create_session, increment_session_count
from terminal_bouncer.execution_controller import execute_command


def guard_command(
    command: str,
    config: Optional[Config] = None,
    cwd: Optional[str] = None,
    repo_path: Optional[str] = None,
) -> dict:
    """
    Evaluate and optionally execute a command.

    Returns a dict with:
      final_action, llm_decision, confidence, risk_level, reason, executed, log
      stdout/stderr/returncode (only when executed=True)
    """
    if config is None:
        config = Config()

    cwd = cwd or os.getcwd()
    guard_dir = os.path.join(cwd, config.guard_dir)
    repo = repo_path or cwd
    session = get_or_create_session(guard_dir, repo)
    start = time.monotonic()

    # 1. Rule engine fast check
    blocked_by_rule, rule_reason = check_rules(command)
    if blocked_by_rule:
        llm_result = {
            "decision": "DENY",
            "confidence": 1.0,
            "risk_level": "HIGH",
            "reason": rule_reason,
        }
        entry = _build_entry(
            command, session, repo, cwd, llm_result,
            final_action="BLOCK", executed=False,
            rule_triggered=True, fallback_used=False,
            raw_responses=[], latency_ms=_elapsed(start),
        )
        log_event(entry, guard_dir)
        increment_session_count(guard_dir)
        return {"final_action": "BLOCK", "reason": rule_reason, "log": entry}

    # 2. LLM evaluation with retry
    llm_result, raw_responses, fallback_used = evaluate_command(command, config)

    # 3. Decision
    final_action = decide(llm_result, config)

    # 4. Execute if approved
    executed = False
    stdout = stderr = ""
    returncode = None

    if final_action == "EXECUTE":
        returncode, stdout, stderr = execute_command(command, cwd=cwd)
        executed = True

    # 5. Log
    entry = _build_entry(
        command, session, repo, cwd, llm_result,
        final_action=final_action, executed=executed,
        rule_triggered=False, fallback_used=fallback_used,
        raw_responses=raw_responses, latency_ms=_elapsed(start),
    )
    log_event(entry, guard_dir)
    increment_session_count(guard_dir)

    result = {
        "final_action": final_action,
        "llm_decision": llm_result["decision"],
        "confidence": llm_result["confidence"],
        "risk_level": llm_result["risk_level"],
        "reason": llm_result["reason"],
        "executed": executed,
        "log": entry,
    }
    if executed:
        result["stdout"] = stdout
        result["stderr"] = stderr
        result["returncode"] = returncode

    return result


def _elapsed(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _get_git_branch(cwd: str) -> Optional[str]:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, cwd=cwd, timeout=5,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def _build_entry(
    command: str,
    session: dict,
    repo: str,
    cwd: str,
    llm_result: dict,
    final_action: str,
    executed: bool,
    rule_triggered: bool,
    fallback_used: bool,
    raw_responses: list,
    latency_ms: int,
) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session["session_id"],
        "repo_path": repo,
        "command": command,
        "command_hash": hash_command(command),
        "classification": classify_command(command),
        "llm_decision": llm_result["decision"],
        "confidence": llm_result["confidence"],
        "risk_level": llm_result["risk_level"],
        "final_action": final_action,
        "executed": executed,
        "reason": llm_result["reason"],
        "rule_triggered": rule_triggered,
        "fallback_used": fallback_used,
        "raw_responses": raw_responses,
        "latency_ms": latency_ms,
        "cwd": cwd,
        "branch": _get_git_branch(cwd),
        "attempts": len(raw_responses),
    }
