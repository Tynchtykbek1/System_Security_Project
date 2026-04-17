from __future__ import annotations

import json
from pathlib import Path

from app import audit, config, crypto_utils


def main() -> None:
    print(f"Initializing secure edge-cloud project under: {config.DATA_DIR}")
    print()

    for node_id in config.EDGE_NODE_IDS:
        _setup_edge_node(node_id)
        print()

    _setup_cloud()
    print()
    print("Setup complete.")


def _setup_edge_node(node_id: str) -> None:
    print(f"[{node_id}] Initializing edge node")
    _ensure_node_directories(node_id)
    _ensure_ed25519_keypair(node_id)
    _ensure_fernet_key(node_id)
    _ensure_audit_log(node_id)
    _ensure_nonce_cache(node_id)
    _ensure_local_vault_metadata_if_needed(node_id)


def _setup_cloud() -> None:
    node_id = config.CLOUD
    print(f"[{node_id}] Initializing cloud node")
    _ensure_node_directories(node_id)
    _ensure_json_file(config.get_registered_nodes_path(), {}, "registered node registry")
    _ensure_audit_log(node_id)
    _ensure_nonce_cache(node_id)
    _ensure_directory(config.get_cloud_backups_dir(), "cloud backups directory")


def _ensure_node_directories(node_id: str) -> None:
    _ensure_directory(config.get_node_data_dir(node_id), "data directory")
    _ensure_directory(config.get_node_keys_dir(node_id), "keys directory")
    _ensure_directory(config.get_node_state_dir(node_id), "state directory")
    _ensure_directory(config.get_node_logs_dir(node_id), "logs directory")


def _ensure_ed25519_keypair(node_id: str) -> None:
    private_key_path = config.get_private_key_path(node_id)
    public_key_path = config.get_public_key_path(node_id)

    if private_key_path.exists() and public_key_path.exists():
        print(f"  - Ed25519 key pair already exists: {private_key_path.name}, {public_key_path.name}")
        return

    if private_key_path.exists():
        print("  - Private key exists but public key is missing, recreating public key from private key")
        private_key = crypto_utils.load_private_key_from_file(private_key_path)
        public_key = crypto_utils.get_ed25519_public_key(private_key)
        crypto_utils.save_public_key_to_file(public_key, public_key_path)
        print(f"    kept existing {private_key_path}")
        print(f"    created {public_key_path}")
        return

    if public_key_path.exists():
        print("  - Public key exists but private key is missing, regenerating a fresh matching key pair")
    else:
        print("  - Creating Ed25519 key pair")

    private_key = crypto_utils.generate_ed25519_private_key()
    public_key = crypto_utils.get_ed25519_public_key(private_key)
    crypto_utils.save_private_key_to_file(private_key, private_key_path)
    crypto_utils.save_public_key_to_file(public_key, public_key_path)
    print(f"    created {private_key_path}")
    print(f"    created {public_key_path}")


def _ensure_fernet_key(node_id: str) -> None:
    fernet_key_path = config.get_fernet_key_path(node_id)
    if fernet_key_path.exists():
        print(f"  - Fernet key already exists: {fernet_key_path.name}")
        return

    crypto_utils.save_fernet_key_to_file(crypto_utils.generate_fernet_key(), fernet_key_path)
    print(f"  - Created Fernet key: {fernet_key_path}")


def _ensure_audit_log(node_id: str) -> None:
    audit_log_path = config.get_audit_log_path(node_id)
    if audit_log_path.exists():
        print(f"  - Audit log already exists: {audit_log_path.name}")
        return

    audit.ensure_audit_log_exists(node_id)
    print(f"  - Created audit log: {audit_log_path}")


def _ensure_nonce_cache(node_id: str) -> None:
    _ensure_json_file(config.get_nonce_cache_path(node_id), [], "nonce cache")


def _ensure_local_vault_metadata_if_needed(node_id: str) -> None:
    vault_path = config.get_local_vault_path(node_id)
    metadata_path = _get_local_vault_metadata_path(node_id)

    if metadata_path.exists():
        print(f"  - Local vault metadata already exists: {metadata_path.name}")
        return

    if not vault_path.exists():
        print("  - Local vault metadata not needed yet")
        return

    _write_json_file(
        metadata_path,
        {
            "node_id": node_id,
            "vault_version": 1,
            "ciphertext_b64": None,
            "integrity_hash": None,
        },
    )
    print(f"  - Created local vault metadata: {metadata_path}")


def _ensure_directory(path: Path, label: str) -> None:
    if path.exists():
        print(f"  - {label.capitalize()} already exists: {path}")
        return

    path.mkdir(parents=True, exist_ok=True)
    print(f"  - Created {label}: {path}")


def _ensure_json_file(path: Path, default: object, label: str) -> None:
    if path.exists():
        print(f"  - {label.capitalize()} already exists: {path.name}")
        return

    _write_json_file(path, default)
    print(f"  - Created {label}: {path}")


def _write_json_file(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _get_local_vault_metadata_path(node_id: str) -> Path:
    vault_path = config.get_local_vault_path(node_id)
    return vault_path.with_name(f"{vault_path.stem}_metadata.json")


if __name__ == "__main__":
    main()
