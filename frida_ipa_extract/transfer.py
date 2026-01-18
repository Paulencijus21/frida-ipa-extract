import os
from typing import Dict, List, Optional, Tuple


def enumerate_bundle_files(dumper, bundle_path: str) -> Tuple[List[str], List[str], Dict[str, int], int]:
    listing = dumper.list_files(bundle_path)
    dirs = listing.get("dirs", [])
    files = listing.get("files", [])
    sizes: Dict[str, int] = {}
    total = 0

    for rel in files:
        remote_path = f"{bundle_path}/{rel}"
        stat = dumper.stat_path(remote_path)
        if not stat.get("exists") or stat.get("isDir"):
            continue
        size = int(stat.get("size", 0))
        sizes[rel] = size
        total += size

    return dirs, files, sizes, total


def pull_bundle_via_frida(
    dumper,
    bundle_path: str,
    local_dir: str,
    chunk_size: int = 256 * 1024,
    *,
    files: Optional[List[str]] = None,
    dirs: Optional[List[str]] = None,
    sizes: Optional[Dict[str, int]] = None,
    progress=None,
):
    if files is None or dirs is None or sizes is None:
        dirs, files, sizes, _ = enumerate_bundle_files(dumper, bundle_path)

    os.makedirs(local_dir, exist_ok=True)
    for rel in sorted(dirs, key=len):
        os.makedirs(os.path.join(local_dir, rel), exist_ok=True)

    for rel in files:
        remote_path = f"{bundle_path}/{rel}"
        local_path = os.path.join(local_dir, rel)
        pull_file_via_frida(
            dumper,
            remote_path,
            local_path,
            chunk_size=chunk_size,
            size=sizes.get(rel),
            progress=progress,
        )


def pull_file_via_frida(
    dumper,
    remote_path: str,
    local_path: str,
    chunk_size: int = 256 * 1024,
    *,
    size: Optional[int] = None,
    progress=None,
):
    if size is None:
        stat = dumper.stat_path(remote_path)
        if not stat.get("exists"):
            raise RuntimeError(f"Remote path not found: {remote_path}")
        if stat.get("isDir"):
            raise RuntimeError(f"Remote path is a directory: {remote_path}")
        size = int(stat.get("size", 0))

    local_dir = os.path.dirname(local_path)
    if local_dir:
        os.makedirs(local_dir, exist_ok=True)

    with open(local_path, "wb") as handle:
        offset = 0
        while offset < size:
            read_size = min(chunk_size, size - offset)
            chunk = dumper.read_file(remote_path, offset, read_size)
            if not chunk:
                break
            handle.write(chunk)
            offset += len(chunk)
            if progress is not None:
                progress.update(len(chunk))
