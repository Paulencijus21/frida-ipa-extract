import os
import posixpath
import socket
import stat
import threading
import select
from dataclasses import dataclass

import paramiko


@dataclass
class SshConfig:
    host: str
    port: int
    username: str
    password: str


class SshClient:
    def __init__(self, config: SshConfig, timeout: int = 10):
        self._config = config
        self._timeout = timeout
        self._client = None

    def connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            timeout=self._timeout,
        )
        self._client = client

    @property
    def transport(self):
        if not self._client:
            raise RuntimeError("SSH client not connected.")
        return self._client.get_transport()

    def open_sftp(self):
        if not self._client:
            raise RuntimeError("SSH client not connected.")
        return self._client.open_sftp()

    def stat(self, remote_path: str):
        with self.open_sftp() as sftp:
            return sftp.stat(remote_path)

    def walk(self, remote_dir: str):
        files = []
        dirs = []
        with self.open_sftp() as sftp:
            self._walk_sftp(sftp, remote_dir, "", files, dirs)
        return files, dirs

    def _walk_sftp(self, sftp, remote_dir: str, rel_base: str, files, dirs):
        for entry in sftp.listdir_attr(remote_dir):
            remote_path = posixpath.join(remote_dir, entry.filename)
            rel_path = posixpath.join(rel_base, entry.filename) if rel_base else entry.filename
            if stat.S_ISDIR(entry.st_mode):
                dirs.append(rel_path)
                self._walk_sftp(sftp, remote_path, rel_path, files, dirs)
            else:
                files.append((remote_path, rel_path, entry.st_size))

    def download_file(self, remote_path: str, local_path: str, progress=None):
        local_dir = os.path.dirname(local_path)
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)
        with self.open_sftp() as sftp:
            self._download_file_sftp(sftp, remote_path, local_path, progress=progress)

    def download_dir(self, remote_dir: str, local_dir: str, *, files=None, dirs=None, progress=None):
        if files is None or dirs is None:
            files, dirs = self.walk(remote_dir)

        os.makedirs(local_dir, exist_ok=True)
        for rel in sorted(dirs, key=len):
            os.makedirs(os.path.join(local_dir, rel), exist_ok=True)

        with self.open_sftp() as sftp:
            for remote_path, rel_path, _size in files:
                local_path = os.path.join(local_dir, rel_path)
                self._download_file_sftp(
                    sftp, remote_path, local_path, progress=progress
                )

    def _download_file_sftp(self, sftp, remote_path: str, local_path: str, progress=None):
        last = 0

        def callback(transferred, total):
            nonlocal last
            if progress is not None:
                progress.update(transferred - last)
            last = transferred

        sftp.get(remote_path, local_path, callback=callback if progress else None)

    def close(self):
        if self._client:
            self._client.close()
            self._client = None


class SshTunnel:
    def __init__(self, ssh_client: SshClient, remote_host: str, remote_port: int):
        self._ssh_client = ssh_client
        self._remote_host = remote_host
        self._remote_port = remote_port
        self._server = None
        self._thread = None
        self._stop_event = threading.Event()
        self._local_port = None

    @property
    def local_port(self):
        return self._local_port

    def start(self, local_host: str = "127.0.0.1", local_port: int = 0):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((local_host, local_port))
        server.listen(100)
        self._server = server
        self._local_port = server.getsockname()[1]

        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        self._thread = thread

    def _accept_loop(self):
        while not self._stop_event.is_set():
            try:
                client, addr = self._server.accept()
            except OSError:
                break
            thread = threading.Thread(
                target=self._handle_client, args=(client, addr), daemon=True
            )
            thread.start()

    def _handle_client(self, client, addr):
        transport = self._ssh_client.transport
        try:
            chan = transport.open_channel(
                "direct-tcpip",
                (self._remote_host, self._remote_port),
                addr,
            )
        except Exception:
            client.close()
            return

        while True:
            rlist, _, _ = select.select([client, chan], [], [], 1.0)
            if client in rlist:
                data = client.recv(1024)
                if not data:
                    break
                chan.sendall(data)
            if chan in rlist:
                data = chan.recv(1024)
                if not data:
                    break
                client.sendall(data)

        chan.close()
        client.close()

    def stop(self):
        self._stop_event.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        self._thread = None
