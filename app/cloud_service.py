from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException

from app import audit, config, crypto_utils, storage
from app.models import (
    AuditLogResponse,
    AuditEvent,
    HealthResponse,
    RegisterNodeRequest,
    RegisterNodeResponse,
    RetrieveBackupRequest,
    RetrieveBackupResponse,
    StoreBackupRequest,
    StoreBackupResponse,
)

app = FastAPI(title="Secure Edge-Cloud Cloud Service")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Return a minimal health response for the cloud service."""
    return HealthResponse(service="cloud_service", node_id=config.CLOUD)


@app.post("/register-node", response_model=RegisterNodeResponse)
def register_node(request: RegisterNodeRequest) -> RegisterNodeResponse:
    """Register a node public key after validating freshness, nonce, and signature."""
    node_id = _require_edge_node(request.node_id)
    _require_fresh_timestamp(request.timestamp)
    _require_unused_nonce(node_id, request.nonce, request.timestamp)

    public_key = _load_public_key_from_b64(request.public_key_b64)
    signed_message = _build_register_message(request)
    if not _verify_request_signature(public_key, signed_message, request.signature_b64):
        _record_nonce(node_id, request.nonce, request.timestamp)
        _append_audit_event(
            actor=node_id,
            target=config.CLOUD,
            action="signature_rejected",
            status="failure",
            details={"reason": "invalid registration signature"},
        )
        raise HTTPException(status_code=401, detail="Invalid signature")

    registry = storage.load_registered_nodes()
    existing_record = registry.get(node_id)
    if isinstance(existing_record, dict):
        existing_public_key = existing_record.get("public_key_b64")
        if existing_public_key == request.public_key_b64:
            _record_nonce(node_id, request.nonce, request.timestamp)
            _append_audit_event(
                actor=node_id,
                target=config.CLOUD,
                action="register_node",
                status="success",
                details={"node_id": node_id, "result": "already_registered"},
            )
            return RegisterNodeResponse(
                registered=True,
                node_id=node_id,
                message="Node already registered with the same public key",
            )

        _record_nonce(node_id, request.nonce, request.timestamp)
        _append_audit_event(
            actor=node_id,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"reason": "public key mismatch for existing registration", "node_id": node_id},
        )
        raise HTTPException(
            status_code=409,
            detail="Node is already registered with a different public key",
        )

    registry[node_id] = {
        "node_id": node_id,
        "public_key_b64": request.public_key_b64,
        "registered_at": _utc_now().isoformat(),
    }
    storage.save_registered_nodes(registry)
    _record_nonce(node_id, request.nonce, request.timestamp)

    _append_audit_event(
        actor=node_id,
        target=config.CLOUD,
        action="register_node",
        status="success",
        details={"node_id": node_id},
    )
    return RegisterNodeResponse(
        registered=True,
        node_id=node_id,
        message="Node registered successfully",
    )


@app.post("/store-backup", response_model=StoreBackupResponse)
def store_backup(request: StoreBackupRequest) -> StoreBackupResponse:
    """Store ciphertext backup metadata for a registered node without decrypting it."""
    node_id = _require_edge_node(request.node_id)
    _require_fresh_timestamp(request.timestamp)
    _require_unused_nonce(node_id, request.nonce, request.timestamp)

    public_key = _get_registered_public_key(node_id)
    signed_message = _build_store_backup_message(request)
    if not _verify_request_signature(public_key, signed_message, request.signature_b64):
        _record_nonce(node_id, request.nonce, request.timestamp)
        _append_audit_event(
            actor=node_id,
            target=config.CLOUD,
            action="signature_rejected",
            status="failure",
            details={"reason": "invalid store-backup signature"},
        )
        raise HTTPException(status_code=401, detail="Invalid signature")

    stored_at = _utc_now()
    storage.save_cloud_backup(
        node_id,
        {
            "node_id": node_id,
            "vault_version": request.vault_version,
            "ciphertext_b64": request.ciphertext_b64,
            "integrity_hash": request.integrity_hash,
            "stored_at": stored_at.isoformat(),
        },
    )
    _record_nonce(node_id, request.nonce, request.timestamp)

    _append_audit_event(
        actor=node_id,
        target=config.CLOUD,
        action="store_backup",
        status="success",
        details={"node_id": node_id, "vault_version": request.vault_version},
    )
    return StoreBackupResponse(
        stored=True,
        node_id=node_id,
        vault_version=request.vault_version,
        stored_at=stored_at,
        message="Backup stored successfully",
    )


@app.post("/retrieve-backup", response_model=RetrieveBackupResponse)
def retrieve_backup(request: RetrieveBackupRequest) -> RetrieveBackupResponse:
    """Return stored ciphertext backup data for a registered node."""
    node_id = _require_edge_node(request.node_id)
    _require_fresh_timestamp(request.timestamp)
    _require_unused_nonce(node_id, request.nonce, request.timestamp)

    public_key = _get_registered_public_key(node_id)
    signed_message = _build_retrieve_backup_message(request)
    if not _verify_request_signature(public_key, signed_message, request.signature_b64):
        _record_nonce(node_id, request.nonce, request.timestamp)
        _append_audit_event(
            actor=node_id,
            target=config.CLOUD,
            action="signature_rejected",
            status="failure",
            details={"reason": "invalid retrieve-backup signature"},
        )
        raise HTTPException(status_code=401, detail="Invalid signature")

    backup = storage.load_cloud_backup(node_id)
    _record_nonce(node_id, request.nonce, request.timestamp)

    if backup is None:
        _append_audit_event(
            actor=node_id,
            target=config.CLOUD,
            action="retrieve_backup",
            status="failure",
            details={"node_id": node_id, "reason": "backup not found"},
        )
        return RetrieveBackupResponse(
            found=False,
            node_id=node_id,
            message="Backup not found",
        )

    stored_at = datetime.fromisoformat(backup["stored_at"])
    _append_audit_event(
        actor=node_id,
        target=config.CLOUD,
        action="retrieve_backup",
        status="success",
        details={
            "node_id": node_id,
            "vault_version": backup["vault_version"],
            "request_reason": request.request_reason,
        },
    )
    return RetrieveBackupResponse(
        found=True,
        node_id=node_id,
        vault_version=backup["vault_version"],
        ciphertext_b64=backup["ciphertext_b64"],
        integrity_hash=backup["integrity_hash"],
        stored_at=stored_at,
        message="Backup retrieved successfully",
    )


@app.get("/access-log", response_model=AuditLogResponse)
def access_log() -> AuditLogResponse:
    """Return the cloud audit log entries."""
    return audit.read_audit_log(config.CLOUD)


def _require_known_node(node_id: str) -> str:
    """Validate and return a known node identifier."""
    try:
        return config.validate_node_id(node_id)
    except ValueError as exc:
        _append_audit_event(
            actor=node_id,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"reason": "unknown node_id"},
        )
        raise HTTPException(status_code=400, detail="Unknown node_id") from exc


def _require_edge_node(node_id: str) -> str:
    """Validate and return an edge-node identifier, rejecting the cloud node."""
    validated_node_id = _require_known_node(node_id)
    if validated_node_id not in config.EDGE_NODE_IDS:
        _append_audit_event(
            actor=node_id,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"reason": "edge node_id required"},
        )
        raise HTTPException(status_code=400, detail="Only edge node_id values are allowed")
    return validated_node_id


def _require_fresh_timestamp(timestamp: datetime) -> None:
    """Reject requests whose timestamps are outside the configured tolerance."""
    now = _utc_now()
    age = abs(now - timestamp)
    if age > timedelta(seconds=config.TIMESTAMP_TOLERANCE_SECONDS):
        _append_audit_event(
            actor=config.CLOUD,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"reason": "stale timestamp", "timestamp": timestamp.isoformat()},
        )
        raise HTTPException(status_code=400, detail="Stale or invalid timestamp")


def _require_unused_nonce(node_id: str, nonce: str, timestamp: datetime) -> None:
    """Reject replayed nonces after pruning expired cache entries."""
    entries = _prune_nonce_entries(storage.load_nonce_cache(node_id))
    if any(entry.get("nonce") == nonce for entry in entries):
        storage.save_nonce_cache(node_id, entries)
        _append_audit_event(
            actor=node_id,
            target=config.CLOUD,
            action="replay_rejected",
            status="failure",
            details={"nonce": nonce, "timestamp": timestamp.isoformat()},
        )
        raise HTTPException(status_code=409, detail="Replay detected")

    storage.save_nonce_cache(node_id, entries)


def _record_nonce(node_id: str, nonce: str, timestamp: datetime) -> None:
    """Store a newly accepted nonce with bounded retention."""
    entries = _prune_nonce_entries(storage.load_nonce_cache(node_id))
    entries.append({"nonce": nonce, "timestamp": timestamp.isoformat()})
    entries = entries[-config.MAX_NONCE_CACHE_ENTRIES :]
    storage.save_nonce_cache(node_id, entries)


def _prune_nonce_entries(entries: list[dict]) -> list[dict]:
    """Remove expired nonce records using the configured TTL."""
    cutoff = _utc_now() - timedelta(seconds=config.NONCE_TTL_SECONDS)
    valid_entries: list[dict] = []

    for entry in entries:
        timestamp_text = entry.get("timestamp")
        if not isinstance(timestamp_text, str):
            continue
        try:
            entry_timestamp = datetime.fromisoformat(timestamp_text)
        except ValueError:
            continue
        if entry_timestamp >= cutoff:
            valid_entries.append(entry)

    return valid_entries


def _get_registered_public_key(node_id: str) -> Ed25519PublicKey:
    """Load a registered node public key from the cloud registry."""
    registry = storage.load_registered_nodes()
    node_record = registry.get(node_id)
    if not isinstance(node_record, dict) or "public_key_b64" not in node_record:
        _append_audit_event(
            actor=node_id,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"reason": "node not registered"},
        )
        raise HTTPException(status_code=403, detail="Node is not registered")

    return _load_public_key_from_b64(node_record["public_key_b64"])


def _load_public_key_from_b64(public_key_b64: str) -> Ed25519PublicKey:
    """Decode a raw Ed25519 public key from base64."""
    try:
        key_bytes = base64.b64decode(public_key_b64, validate=True)
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid public key") from exc


def _verify_request_signature(
    public_key: Ed25519PublicKey,
    message: bytes,
    signature_b64: str,
) -> bool:
    """Decode and verify a base64 Ed25519 signature."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except ValueError:
        return False
    return crypto_utils.verify_signature(public_key, message, signature)


def _build_register_message(request: RegisterNodeRequest) -> bytes:
    """Build the canonical signed payload for node registration."""
    return _serialize_signed_payload(
        {
            "action": "register-node",
            "node_id": request.node_id,
            "public_key_b64": request.public_key_b64,
            "timestamp": request.timestamp.isoformat(),
            "nonce": request.nonce,
        }
    )


def _build_store_backup_message(request: StoreBackupRequest) -> bytes:
    """Build the canonical signed payload for storing ciphertext backups."""
    return _serialize_signed_payload(
        {
            "action": "store-backup",
            "node_id": request.node_id,
            "vault_version": request.vault_version,
            "ciphertext_b64": request.ciphertext_b64,
            "integrity_hash": request.integrity_hash,
            "timestamp": request.timestamp.isoformat(),
            "nonce": request.nonce,
        }
    )


def _build_retrieve_backup_message(request: RetrieveBackupRequest) -> bytes:
    """Build the canonical signed payload for backup retrieval."""
    return _serialize_signed_payload(
        {
            "action": "retrieve-backup",
            "node_id": request.node_id,
            "request_reason": request.request_reason,
            "timestamp": request.timestamp.isoformat(),
            "nonce": request.nonce,
        }
    )


def _serialize_signed_payload(payload: dict[str, object]) -> bytes:
    """Serialize signed request fields deterministically."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _append_audit_event(
    actor: str,
    target: str,
    action: str,
    status: str,
    details: dict[str, object],
) -> None:
    """Append a cloud audit event using the shared audit helpers."""
    audit.append_audit_event(
        config.CLOUD,
        AuditEvent(
            event_id=str(uuid4()),
            actor=actor,
            target=target,
            action=action,
            status=status,
            timestamp=_utc_now(),
            details=details,
        ),
    )


def _utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)
