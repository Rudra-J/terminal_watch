from unittest.mock import patch
from terminal_bouncer.__main__ import main


def test_module_accepts_command_argument():
    with patch("terminal_bouncer.__main__.guard_command") as mock_guard:
        mock_guard.return_value = {
            "final_action": "BLOCK",
            "reason": "rule triggered",
            "log": {},
        }
        with patch("sys.argv", ["terminal_bouncer", "rm -rf /"]):
            main()
    mock_guard.assert_called_once_with("rm -rf /", config=None, cwd=None)


def test_module_reads_from_stdin_when_no_arg():
    with patch("terminal_bouncer.__main__.guard_command") as mock_guard, \
         patch("sys.argv", ["terminal_bouncer"]), \
         patch("sys.stdin.read", return_value="ls\n"):
        mock_guard.return_value = {
            "final_action": "EXECUTE",
            "executed": True,
            "log": {},
        }
        main()
    mock_guard.assert_called_once_with("ls", config=None, cwd=None)
