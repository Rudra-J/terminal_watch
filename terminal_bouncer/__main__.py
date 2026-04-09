import json
import sys
from terminal_bouncer.guard import guard_command


def main():
    if len(sys.argv) > 1:
        command = sys.argv[1]
    else:
        command = sys.stdin.read().strip()

    result = guard_command(command, config=None, cwd=None)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
