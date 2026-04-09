# terminal_bouncer

A local AI-powered safety guard that intercepts shell commands proposed by AI agents (like Claude Code), evaluates them for risk using a local LLM via Ollama, and decides whether to execute, block, or ask for confirmation — with a full audit trail.

## What it does

Before a shell command runs, `terminal_bouncer` puts it through a multi-layer evaluation pipeline:

```
Command
  ↓
Rule Engine          — instant block for known-dangerous patterns
  ↓
Ollama LLM           — local AI evaluates intent and risk
  ↓
Output Validation    — strict schema + semantic checks on LLM response
  ↓
Retry / Fallback     — up to 3 attempts; safe DENY if all fail
  ↓
Decision Engine      — threshold-based EXECUTE / BLOCK / ASK
  ↓
Execution + Logging  — runs approved commands, logs everything to JSONL
```

## Why it exists

AI coding agents propose shell commands that can be destructive, exfiltrating, or subtly dangerous. A single-command safety check is not enough — patterns only emerge over time. `terminal_bouncer` provides:

- **Instant blocking** of known-dangerous commands (no LLM call needed)
- **LLM-based risk evaluation** using a local model (no data leaves your machine)
- **Strict output validation** — the LLM's response must match a schema or the command is blocked
- **Retry with prompt reinforcement** — bad LLM output triggers a stricter re-prompt
- **Fail-safe fallback** — if the LLM fails repeatedly, the command is denied
- **Persistent audit logs** — every command, decision, and LLM response is recorded per repo

## Installation

Requires Python 3.11+ and [Ollama](https://ollama.ai) running locally.

```bash
git clone https://github.com/Rudra-J/terminal_watch.git
cd terminal_watch
pip install -e ".[dev]"
```

Pull a model in Ollama (default: `llama3`):

```bash
ollama pull llama3
```

## Usage

### CLI

```bash
python -m terminal_bouncer "git push origin main"
```

Output (JSON):

```json
{
  "final_action": "EXECUTE",
  "llm_decision": "ALLOW",
  "confidence": 0.92,
  "risk_level": "LOW",
  "reason": "Standard git push to remote branch",
  "executed": true,
  "stdout": "...",
  "returncode": 0
}
```

### Python API

```python
from terminal_bouncer.guard import guard_command
from terminal_bouncer.config import Config

config = Config(ollama_model="llama3", allow_threshold=0.7)
result = guard_command("rm -rf ./dist", config=config, cwd="/my/project")

print(result["final_action"])  # BLOCK, EXECUTE, or ASK
```

## Configuration

All settings live in `terminal_bouncer/config.py`:

| Field | Default | Description |
|-------|---------|-------------|
| `ollama_url` | `http://localhost:11434` | Ollama API endpoint |
| `ollama_model` | `llama3` | Model to use for evaluation |
| `allow_threshold` | `0.7` | Min confidence to EXECUTE |
| `deny_threshold` | `0.4` | Max confidence before BLOCK |
| `max_retries` | `3` | LLM retry attempts |
| `temperature` | `0.1` | LLM temperature (low = deterministic) |
| `top_p` | `0.9` | LLM top-p sampling |
| `guard_dir` | `.claude_guard` | Dir for logs (relative to cwd) |

## LLM Output Contract

The guard expects the LLM to return strictly:

```json
{
  "decision": "ALLOW | DENY | ASK",
  "confidence": 0.0,
  "risk_level": "LOW | MEDIUM | HIGH",
  "reason": "specific explanation"
}
```

Responses that fail schema or semantic checks (e.g. `ALLOW` + `HIGH` risk) are rejected and retried with a stricter prompt.

## Audit Logs

Every command evaluation is appended to `.claude_guard/history.jsonl` in the working directory:

```json
{
  "timestamp": "2026-04-09T16:00:00Z",
  "session_id": "uuid",
  "command": "rm -rf ./dist",
  "command_hash": "sha256...",
  "classification": "FILE_OPS",
  "llm_decision": "DENY",
  "confidence": 0.95,
  "risk_level": "HIGH",
  "final_action": "BLOCK",
  "executed": false,
  "reason": "Recursively deletes build directory without confirmation",
  "rule_triggered": false,
  "fallback_used": false,
  "attempts": 1,
  "latency_ms": 340,
  "branch": "main"
}
```

## Rule Engine

Commands matching these patterns are blocked instantly without an LLM call:

- `rm -rf /` or `rm -rf *`
- Fork bombs: `:(){ :|:& };:`
- `dd if=/dev/...`
- `curl/wget ... | bash/sh`
- `mkfs.*`, `chmod -R 777 /`

## Decision Logic

```
DENY decision          → always BLOCK
confidence ≤ 0.4       → BLOCK
ALLOW + confidence ≥ 0.7 → EXECUTE
everything else        → ASK
```

## Project Structure

```
terminal_bouncer/
├── config.py              # Configuration dataclass
├── rule_engine.py         # Instant pattern-based blocking
├── classifier.py          # Command type tagging (GIT, FILE_OPS, etc.)
├── hasher.py              # SHA-256 command fingerprinting
├── validator.py           # LLM output schema + semantic validation
├── llm_client.py          # Ollama HTTP client + prompt builder
├── retry.py               # Retry loop, backoff, fallback
├── decision_engine.py     # EXECUTE / BLOCK / ASK thresholds
├── logger.py              # JSONL audit log + session tracking
├── execution_controller.py # subprocess runner
├── audit.py               # Stub: future behavioral anomaly detection
├── guard.py               # Main orchestrator
└── __main__.py            # CLI entry point
```

## Running Tests

```bash
pytest
```

96 tests, 0 failures.

## Future Direction

- **Window-based audit model** — detect slow attacks spread across multiple commands
- **Risk accumulation** — track cumulative risk score per session
- **Claude Code hook integration** — plug directly into Claude Code's `PreToolUse` hook
- **Sequence anomaly detection** — flag `ls → cat → grep → rm` escalation patterns
