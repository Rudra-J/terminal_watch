def classify_command(cmd: str) -> str:
    """Classify a command into a category for logging and analysis."""
    c = cmd.lower().strip()

    if c.startswith("git "):
        return "GIT"

    if any(c.startswith(t) for t in ("pip ", "pip3 ", "npm ", "yarn ", "poetry ")):
        return "INSTALL"

    if c.startswith("python") and (c.startswith("python ") or c.startswith("python3")):
        return "PYTHON"

    if any(c.startswith(token) for token in ("rm ", "cp ", "mv ", "mkdir ", "touch ", "chmod ", "chown ")):
        return "FILE_OPS"

    if any(c.startswith(token) for token in ("curl ", "wget ", "ssh ", "scp ", "nc ", "netstat ")):
        return "NETWORK"

    return "OTHER"
