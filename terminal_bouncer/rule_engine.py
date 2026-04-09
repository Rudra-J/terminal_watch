import re
from typing import Optional


BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+\*",
    r":\(\)\s*\{",                   # fork bomb
    r"dd\s+if=/dev/",
    r"mkfs\.",
    r"chmod\s+-R\s+777\s+/",
    r">\s*/dev/sda",
    r"wget\s+.+\|\s*(ba)?sh",
    r"curl\s+.+\|\s*(ba)?sh",
]

SAFE_PATTERNS = [
    r"^git\s+(status|log|diff|branch|show|fetch|clone)\b",
    r"^ls(\s|$)",
    r"^pwd$",
    r"^echo\s+",
    r"^cat\s+",
]


def check_rules(command: str) -> tuple[bool, Optional[str]]:
    """Return (blocked, reason). blocked=True means immediately deny."""
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            return True, f"Matches blocked pattern: {pattern}"
    return False, None


def is_safe_command(command: str) -> bool:
    """Return True if command matches known-safe patterns."""
    for pattern in SAFE_PATTERNS:
        if re.match(pattern, command.strip()):
            return True
    return False
