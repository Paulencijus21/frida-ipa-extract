import re
import sys


def sanitize_filename(name: str, fallback: str = "app") -> str:
    if not name:
        return fallback
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name.strip())
    return safe or fallback


def prompt_choice(options, prompt: str):
    if not sys.stdin.isatty():
        raise RuntimeError("Interactive selection requires a TTY.")
    while True:
        choice = input(prompt).strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(options):
                return options[idx - 1]
        print("Invalid selection. Try again.")
