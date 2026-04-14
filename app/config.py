from __future__ import annotations

from pathlib import Path
from typing import Final

# Stable node identifiers used across edge and cloud services.
EDGE_A: Final[str] = "edgeA"
EDGE_B: Final[str] = "edgeB"
EDGE_C: Final[str] = "edgeC"
CLOUD: Final[str] = "cloud"

NODE_IDS: Final[tuple[str, ...]] = (EDGE_A, EDGE_B, EDGE_C, CLOUD)
EDGE_NODE_IDS: Final[tuple[str, ...]] = (EDGE_A, EDGE_B, EDGE_C)
ALLOWED_RECOVERY_REASONS: Final[tuple[str, ...]] = ("recovery", "sync", "audit")

# Fixed service ports for local multi-node development.
NODE_PORTS: Final[dict[str, int]] = {
    EDGE_A: 8101,
    EDGE_B: 8102,
    EDGE_C: 8103,
    CLOUD: 8200,
}

# Base directories used by runtime services.
PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
DATA_DIR: Final[Path] = PROJECT_ROOT / "data"
KEYS_DIRNAME: Final[str] = "keys"
STATE_DIRNAME: Final[str] = "state"
BACKUPS_DIRNAME: Final[str] = "backups"
LOGS_DIRNAME: Final[str] = "logs"

# Standard per-node filenames so both services read/write the same structure.
PRIVATE_KEY_FILENAME: Final[str] = "ed25519_private.pem"
PUBLIC_KEY_FILENAME: Final[str] = "ed25519_public.pem"
FERNET_KEY_FILENAME: Final[str] = "fernet.key"
LOCAL_VAULT_FILENAME: Final[str] = "local_vault.enc"
REGISTERED_NODES_FILENAME: Final[str] = "registered_nodes.json"
AUDIT_LOG_FILENAME: Final[str] = "audit_log.json"
NONCE_CACHE_FILENAME: Final[str] = "nonce_cache.json"

# Application-level policy constants.
TIMESTAMP_TOLERANCE_SECONDS: Final[int] = 300
NONCE_TTL_SECONDS: Final[int] = 600
MAX_NONCE_CACHE_ENTRIES: Final[int] = 10_000


def validate_node_id(node_id: str) -> str:
    """Return a validated node identifier or raise ValueError."""
    if node_id not in NODE_IDS:
        raise ValueError(f"Unknown node_id: {node_id}")
    return node_id


def get_node_port(node_id: str) -> int:
    """Return the configured port for a known node."""
    return NODE_PORTS[validate_node_id(node_id)]


def get_node_data_dir(node_id: str) -> Path:
    """Return the base runtime data directory for a node."""
    return DATA_DIR / validate_node_id(node_id)


def get_node_keys_dir(node_id: str) -> Path:
    """Return the directory where a node stores key material."""
    return get_node_data_dir(node_id) / KEYS_DIRNAME


def get_node_state_dir(node_id: str) -> Path:
    """Return the directory where a node stores JSON state."""
    return get_node_data_dir(node_id) / STATE_DIRNAME


def get_node_logs_dir(node_id: str) -> Path:
    """Return the directory where a node stores audit logs."""
    return get_node_data_dir(node_id) / LOGS_DIRNAME


def get_private_key_path(node_id: str) -> Path:
    """Return the Ed25519 private-key path for a node."""
    return get_node_keys_dir(node_id) / PRIVATE_KEY_FILENAME


def get_public_key_path(node_id: str) -> Path:
    """Return the Ed25519 public-key path for a node."""
    return get_node_keys_dir(node_id) / PUBLIC_KEY_FILENAME


def get_fernet_key_path(node_id: str) -> Path:
    """Return the Fernet key path for a node."""
    return get_node_keys_dir(node_id) / FERNET_KEY_FILENAME


def get_local_vault_path(node_id: str) -> Path:
    """Return the local encrypted vault metadata path for an edge node."""
    return get_node_state_dir(node_id) / LOCAL_VAULT_FILENAME


def get_cloud_backups_dir() -> Path:
    """Return the cloud directory where per-node backups are stored."""
    return get_node_state_dir(CLOUD) / BACKUPS_DIRNAME


def get_cloud_backup_path(node_id: str) -> Path:
    """Return the cloud-side backup path for a node's stored ciphertext."""
    return get_cloud_backups_dir() / f"{validate_node_id(node_id)}_backup.json"


def get_registered_nodes_path() -> Path:
    """Return the shared cloud registry file path for known nodes."""
    return get_node_state_dir(CLOUD) / REGISTERED_NODES_FILENAME


def get_audit_log_path(node_id: str) -> Path:
    """Return the audit log file path for a node."""
    return get_node_logs_dir(node_id) / AUDIT_LOG_FILENAME


def get_nonce_cache_path(node_id: str) -> Path:
    """Return the replay-protection nonce cache path for a node."""
    return get_node_state_dir(node_id) / NONCE_CACHE_FILENAME
