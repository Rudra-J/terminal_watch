from unittest.mock import patch, MagicMock
from terminal_bouncer.execution_controller import execute_command


def _mock_result(returncode=0, stdout="", stderr=""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def test_returns_stdout_on_success():
    with patch("terminal_bouncer.execution_controller.subprocess.run",
               return_value=_mock_result(stdout="hello\n")):
        returncode, stdout, stderr = execute_command("echo hello")
    assert returncode == 0
    assert stdout == "hello\n"
    assert stderr == ""

def test_returns_stderr_on_failure():
    with patch("terminal_bouncer.execution_controller.subprocess.run",
               return_value=_mock_result(returncode=1, stderr="not found")):
        returncode, stdout, stderr = execute_command("badcmd")
    assert returncode == 1
    assert stderr == "not found"

def test_passes_cwd_to_subprocess():
    with patch("terminal_bouncer.execution_controller.subprocess.run",
               return_value=_mock_result()) as mock_run:
        execute_command("ls", cwd="/tmp")
    assert mock_run.call_args[1]["cwd"] == "/tmp"

def test_uses_shell_true():
    with patch("terminal_bouncer.execution_controller.subprocess.run",
               return_value=_mock_result()) as mock_run:
        execute_command("ls")
    assert mock_run.call_args[1]["shell"] is True
