import subprocess
from typing import Optional


def execute_command(
    command: str, cwd: Optional[str] = None
) -> tuple[int, str, str]:
    """Execute command via shell. Returns (returncode, stdout, stderr)."""
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    return result.returncode, result.stdout, result.stderr
