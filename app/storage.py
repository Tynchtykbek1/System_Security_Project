from __future__ import annotations

import json
import os
import tempfile
import threading
from contextlib import contextmanager
from json import JSONDecodeError
from pathlib import Path
from typing import Iterator

from app import config

_LOCKS_GUARD = threading.Lock()
_FILE_LOCKS: dict[str, threading.RLock] = {}
_HELD_LOCKS = threading.local()


@contextmanager
def file_lock(file_path: str | Path) -> Iterator[None]:
    """Serialize read-modify-write access to a specific state file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_key = str(path.resolve())
    with _LOCKS_GUARD:
        thread_lock = _FILE_LOCKS.setdefault(lock_key, threading.RLock())

    held_locks = getattr(_HELD_LOCKS, "counts", None)
    if held_locks is None:
        held_locks = {}
        _HELD_LOCKS.counts = held_locks

    if held_locks.get(lock_key, 0) > 0:
        held_locks[lock_key] += 1
        try:
            yield
        finally:
            held_locks[lock_key] -= 1
        return

    lock_path = path.with_name(f"{path.name}.lock")
    with thread_lock:
        with lock_path.open("a+b") as lock_file:
            _lock_file(lock_file)
            held_locks[lock_key] = 1
            try:
                yield
            finally:
                held_locks.pop(lock_key, None)
                _unlock_file(lock_file)


def _lock_file(lock_file: object) -> None:
    if os.name == "nt":
        import msvcrt

        lock_file.seek(0)
        if lock_file.read(1) == b"":
            lock_file.seek(0)
            lock_file.write(b"\0")
            lock_file.flush()
        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        return

    import fcntl

    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)


def _unlock_file(lock_file: object) -> None:
    if os.name == "nt":
        import msvcrt

        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def read_json_file(file_path: str | Path, default: object) -> object:
    """Read JSON data from disk and return a fallback value if the file is missing."""
    path = Path(file_path)
    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as file_obj:
            return json.load(file_obj)
    except JSONDecodeError:
        return default


def write_json_file(file_path: str | Path, data: object) -> None:
    """Write JSON data to disk using an atomic replace."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write into the target directory first so os.replace stays atomic.
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as temp_file:
        json.dump(data, temp_file, indent=2, sort_keys=True)
        temp_file.write("\n")
        temp_path = Path(temp_file.name)

    os.replace(temp_path, path)


def load_registered_nodes() -> dict:
    """Load the cloud registry of known nodes."""
    data = read_json_file(config.get_registered_nodes_path(), default={})
    if not isinstance(data, dict):
        return {}
    return data


def save_registered_nodes(data: dict) -> None:
    """Persist the cloud registry of known nodes."""
    path = config.get_registered_nodes_path()
    with file_lock(path):
        write_json_file(path, data)


def load_nonce_cache(node_id: str) -> list[dict]:
    """Load a node's nonce cache entries."""
    data = read_json_file(config.get_nonce_cache_path(node_id), default=[])
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def save_nonce_cache(node_id: str, entries: list[dict]) -> None:
    """Persist a node's nonce cache entries."""
    path = config.get_nonce_cache_path(node_id)
    with file_lock(path):
        write_json_file(path, entries)


def load_cloud_backup(node_id: str) -> dict | None:
    """Load the cloud-stored backup JSON for a node."""
    data = read_json_file(config.get_cloud_backup_path(node_id), default=None)
    if not isinstance(data, dict):
        return None
    return data


def save_cloud_backup(node_id: str, backup_data: dict) -> None:
    """Persist the cloud-stored backup JSON for a node."""
    path = config.get_cloud_backup_path(node_id)
    with file_lock(path):
        write_json_file(path, backup_data)


def load_local_vault_metadata(node_id: str) -> dict | None:
    """Load JSON metadata associated with a node's encrypted local vault."""
    data = read_json_file(_get_local_vault_metadata_path(node_id), default=None)
    if not isinstance(data, dict):
        return None
    return data


def save_local_vault_metadata(node_id: str, metadata: dict) -> None:
    """Persist JSON metadata associated with a node's encrypted local vault."""
    path = _get_local_vault_metadata_path(node_id)
    with file_lock(path):
        write_json_file(path, metadata)


def load_local_vault_ciphertext(node_id: str) -> bytes | None:
    """Load the encrypted local vault bytes for a node."""
    path = config.get_local_vault_path(node_id)
    if not path.exists():
        return None

    with path.open("rb") as file_obj:
        return file_obj.read()


def save_local_vault_ciphertext(node_id: str, ciphertext: bytes) -> None:
    """Persist the encrypted local vault bytes for a node atomically."""
    path = config.get_local_vault_path(node_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write into the destination directory first so the final replace is atomic.
    with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as temp_file:
        temp_file.write(ciphertext)
        temp_path = Path(temp_file.name)

    os.replace(temp_path, path)


def local_vault_exists(node_id: str) -> bool:
    """Return whether the encrypted local vault file exists for a node."""
    return config.get_local_vault_path(node_id).exists()


def _get_local_vault_metadata_path(node_id: str) -> Path:
    """Return the JSON metadata path stored alongside local_vault.enc."""
    vault_path = config.get_local_vault_path(node_id)
    return vault_path.with_name(f"{vault_path.stem}_metadata.json")
