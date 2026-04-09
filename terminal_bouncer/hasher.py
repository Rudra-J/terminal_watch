import hashlib


def hash_command(cmd: str) -> str:
    """Return SHA-256 hex digest of the command string."""
    return hashlib.sha256(cmd.encode()).hexdigest()
