from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from app import config


def read_json_file(file_path: str | Path, default: object) -> object:
    """Read JSON data from disk and return a fallback value if the file is missing."""
    path = Path(file_path)
    if not path.exists():
        return default

    with path.open("r", encoding="utf-8") as file_obj:
        return json.load(file_obj)


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
    return read_json_file(config.get_registered_nodes_path(), default={})


def save_registered_nodes(data: dict) -> None:
    """Persist the cloud registry of known nodes."""
    write_json_file(config.get_registered_nodes_path(), data)


def load_nonce_cache(node_id: str) -> list[dict]:
    """Load a node's nonce cache entries."""
    return read_json_file(config.get_nonce_cache_path(node_id), default=[])


def save_nonce_cache(node_id: str, entries: list[dict]) -> None:
    """Persist a node's nonce cache entries."""
    write_json_file(config.get_nonce_cache_path(node_id), entries)


def load_cloud_backup(node_id: str) -> dict | None:
    """Load the cloud-stored backup JSON for a node."""
    return read_json_file(config.get_cloud_backup_path(node_id), default=None)


def save_cloud_backup(node_id: str, backup_data: dict) -> None:
    """Persist the cloud-stored backup JSON for a node."""
    write_json_file(config.get_cloud_backup_path(node_id), backup_data)


def load_local_vault_metadata(node_id: str) -> dict | None:
    """Load JSON metadata associated with a node's encrypted local vault."""
    return read_json_file(_get_local_vault_metadata_path(node_id), default=None)


def save_local_vault_metadata(node_id: str, metadata: dict) -> None:
    """Persist JSON metadata associated with a node's encrypted local vault."""
    write_json_file(_get_local_vault_metadata_path(node_id), metadata)


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
