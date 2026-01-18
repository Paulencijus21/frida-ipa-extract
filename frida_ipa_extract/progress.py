import sys
import time
from typing import Optional


def format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"


class ProgressBar:
    def __init__(self, total: Optional[int], label: str = ""):
        self.total = total
        self.label = label
        self.current = 0
        self._last_render = 0.0
        self._last_len = 0
        self._enabled = sys.stdout.isatty()

    def set_total(self, total: int):
        self.total = total

    def update(self, delta: int):
        if delta <= 0:
            return
        self.current += delta
        self.render()

    def render(self, force: bool = False):
        if not self._enabled:
            return

        now = time.time()
        if not force and (now - self._last_render) < 0.1:
            return
        self._last_render = now

        if self.total:
            ratio = min(self.current / self.total, 1.0)
            width = 30
            filled = int(width * ratio)
            bar = "#" * filled + "-" * (width - filled)
            percent = ratio * 100.0
            line = (
                f"{self.label} [{bar}] {percent:5.1f}% "
                f"{format_bytes(self.current)}/{format_bytes(self.total)}"
            )
        else:
            line = f"{self.label} {format_bytes(self.current)}"

        padding = " " * max(0, self._last_len - len(line))
        sys.stdout.write("\r" + line + padding)
        sys.stdout.flush()
        self._last_len = len(line)

    def finish(self):
        if not self._enabled:
            return
        self.render(force=True)
        sys.stdout.write("\n")
        sys.stdout.flush()
