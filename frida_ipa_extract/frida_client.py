import threading
import time
from pathlib import Path
from typing import Optional

import frida


class FridaDumper:
    def __init__(self, device):
        self._device = device
        self._session = None
        self._script = None
        self._pid = None

    def attach(
        self,
        pid: int,
        retries: int = 3,
        delay: float = 0.5,
        timeout: Optional[float] = None,
    ):
        self._attach_with_retries(pid, retries=retries, delay=delay, timeout=timeout)
        self._pid = pid

    def spawn(
        self,
        target: str,
        retries: int = 3,
        delay: float = 0.5,
        resume: bool = True,
    ):
        pid = self._device.spawn([target])
        self._attach_with_retries(pid, retries=retries, delay=delay)
        if resume:
            self._device.resume(pid)
        self._pid = pid
        return pid

    def _attach_with_retries(
        self, target, retries: int, delay: float, timeout: Optional[float] = None
    ):
        last_error = None
        for attempt in range(1, retries + 1):
            try:
                if retries > 1:
                    print(f"Attach attempt {attempt}/{retries}...")
                if timeout is None:
                    self._session = self._device.attach(target)
                else:
                    cancellable = frida.Cancellable()
                    timer = threading.Timer(timeout, cancellable.cancel)
                    timer.start()
                    try:
                        self._session = self._device.attach(target, cancellable=cancellable)
                    finally:
                        timer.cancel()
                self._load_agent()
                return
            except (frida.TransportError, frida.OperationCancelledError) as exc:
                last_error = exc
                time.sleep(delay)
        if last_error:
            raise last_error

    def _load_agent(self):
        agent_path = Path(__file__).with_name("frida_agent.js")
        source = agent_path.read_text(encoding="utf-8")
        script = self._session.create_script(source)
        script.on("message", self._on_message)
        script.load()
        self._script = script

    def _on_message(self, message, data):
        if message.get("type") == "error":
            description = message.get("stack") or message.get("description")
            print(f"[frida] {description}")
        elif message.get("type") == "send":
            payload = message.get("payload")
            print(f"[frida] {payload}")

    def get_bundle_info(self, retries: int = 40, delay: float = 0.25):
        last_error = None
        for _ in range(retries):
            try:
                return self._script.exports.getbundleinfo()
            except Exception as exc:
                last_error = exc
                time.sleep(delay)
        raise RuntimeError("Failed to fetch bundle info") from last_error

    def dump_executable(self, out_path: str):
        return self._script.exports.dumpexecutable(out_path)

    def get_sandbox_path(self):
        return self._script.exports.getsandboxpath()

    def list_files(self, root_path: str):
        return self._script.exports.listfiles(root_path)

    def stat_path(self, path: str):
        return self._script.exports.statpath(path)

    def read_file(self, path: str, offset: int, size: int):
        return self._script.exports.readfile(path, offset, size)

    def remove_path(self, path: str):
        return self._script.exports.removepath(path)

    def detach(self):
        if self._session:
            self._session.detach()
            self._session = None
            self._script = None
            self._pid = None

    @property
    def pid(self):
        return self._pid
