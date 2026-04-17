from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib import error, request
from uuid import uuid4

from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import serialization
from fastapi import Body, FastAPI, HTTPException

from app import audit, config, crypto_utils, integrity, storage
from app.models import (
    AuditEvent,
    AuditLogResponse,
    EncryptAndBackupResponse,
    HealthResponse,
    IdentityResponse,
    LocalStorageView,
    RecoverFromCloudResponse,
    RegisterNodeRequest,
    RegisterNodeResponse,
    RetrieveBackupRequest,
    RetrieveBackupResponse,
    StoreBackupRequest,
    StoreBackupResponse,
)

app = FastAPI(title="Secure Edge-Cloud Edge Service")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Return a minimal health response for this edge node."""
    return HealthResponse(service="edge_service", node_id=EDGE_NODE_ID)


@app.get("/identity", response_model=IdentityResponse)
def identity() -> IdentityResponse:
    """Return the edge node identity and raw Ed25519 public key bytes in base64."""
    public_key = _load_public_key()
    public_key_b64 = _public_key_to_b64(public_key)
    return IdentityResponse(node_id=EDGE_NODE_ID, public_key_b64=public_key_b64)


@app.post("/encrypt-and-backup", response_model=EncryptAndBackupResponse)
def encrypt_and_backup(plaintext: dict[str, Any] = Body(...)) -> EncryptAndBackupResponse:
    """Encrypt a JSON payload locally, store it, and upload only ciphertext to the cloud."""
    if not plaintext:
        raise HTTPException(status_code=400, detail="Plaintext JSON object is required")

    plaintext_bytes = _serialize_plaintext(plaintext)
    ciphertext = crypto_utils.encrypt_data(_load_fernet_key(), plaintext_bytes)
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    vault_version = _next_vault_version()
    integrity_hash = integrity.compute_sha256_bytes(ciphertext)

    storage.save_local_vault_ciphertext(EDGE_NODE_ID, ciphertext)
    storage.save_local_vault_metadata(
        EDGE_NODE_ID,
        {
            "node_id": EDGE_NODE_ID,
            "vault_version": vault_version,
            "ciphertext_b64": ciphertext_b64,
            "integrity_hash": integrity_hash,
            "updated_at": _utc_now().isoformat(),
        },
    )
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=EDGE_NODE_ID,
        action="encrypt_local",
        status="success",
        details={"vault_version": vault_version},
    )

    _ensure_cloud_registration()
    cloud_response = _store_backup_in_cloud(
        vault_version=vault_version,
        ciphertext_b64=ciphertext_b64,
        integrity_hash=integrity_hash,
    )
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=config.CLOUD,
        action="store_backup",
        status="success",
        details={"vault_version": cloud_response.vault_version},
    )
    return EncryptAndBackupResponse(
        success=True,
        node_id=EDGE_NODE_ID,
        vault_version=cloud_response.vault_version,
        message="Local encryption complete and cloud backup stored",
    )


@app.post("/recover-from-cloud", response_model=RecoverFromCloudResponse)
def recover_from_cloud(request_body: dict[str, Any] | None = Body(None)) -> RecoverFromCloudResponse:
    """Retrieve ciphertext from the cloud, verify integrity, and decrypt locally."""
    safe_request_body = request_body or {}
    request_reason = safe_request_body.get("request_reason", "recovery")
    if not isinstance(request_reason, str):
        raise HTTPException(status_code=400, detail="request_reason must be a string")

    _ensure_cloud_registration()
    backup = _retrieve_backup_from_cloud(request_reason=request_reason)
    if not backup.found or backup.ciphertext_b64 is None or backup.integrity_hash is None:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="retrieve_backup",
            status="failure",
            details={"reason": "backup not found", "request_reason": request_reason},
        )
        raise HTTPException(status_code=404, detail="Backup not found in cloud")

    try:
        ciphertext = base64.b64decode(backup.ciphertext_b64, validate=True)
    except ValueError as exc:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="integrity_mismatch",
            status="failure",
            details={"reason": "cloud returned invalid base64 ciphertext"},
        )
        raise HTTPException(status_code=502, detail="Cloud returned invalid ciphertext") from exc

    actual_hash = integrity.compute_sha256_bytes(ciphertext)
    if not integrity.hashes_match(backup.integrity_hash, actual_hash):
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="integrity_mismatch",
            status="failure",
            details={
                "expected_hash": backup.integrity_hash,
                "actual_hash": actual_hash,
                "vault_version": backup.vault_version,
            },
        )
        raise HTTPException(status_code=409, detail="Integrity verification failed")

    try:
        plaintext_bytes = crypto_utils.decrypt_data(_load_fernet_key(), ciphertext)
    except InvalidToken as exc:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=EDGE_NODE_ID,
            action="request_denied",
            status="failure",
            details={
                "reason": "local decryption failed",
                "vault_version": backup.vault_version,
            },
        )
        raise HTTPException(status_code=422, detail="Unable to decrypt recovered backup") from exc
    plaintext = json.loads(plaintext_bytes.decode("utf-8"))

    storage.save_local_vault_ciphertext(EDGE_NODE_ID, ciphertext)
    storage.save_local_vault_metadata(
        EDGE_NODE_ID,
        {
            "node_id": EDGE_NODE_ID,
            "vault_version": backup.vault_version,
            "ciphertext_b64": backup.ciphertext_b64,
            "integrity_hash": backup.integrity_hash,
            "updated_at": _utc_now().isoformat(),
        },
    )
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=config.CLOUD,
        action="retrieve_backup",
        status="success",
        details={"vault_version": backup.vault_version, "request_reason": request_reason},
    )
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=EDGE_NODE_ID,
        action="decrypt_local",
        status="success",
        details={"vault_version": backup.vault_version},
    )
    return RecoverFromCloudResponse(
        success=True,
        node_id=EDGE_NODE_ID,
        vault_version=backup.vault_version,
        recovered_plaintext=plaintext,
        message="Backup recovered and decrypted locally",
    )


@app.get("/local-storage", response_model=LocalStorageView)
def local_storage() -> LocalStorageView:
    """Return the locally cached ciphertext metadata for this edge node."""
    ciphertext = storage.load_local_vault_ciphertext(EDGE_NODE_ID)
    metadata = storage.load_local_vault_metadata(EDGE_NODE_ID) or {}

    ciphertext_b64 = metadata.get("ciphertext_b64")
    if ciphertext_b64 is None and ciphertext is not None:
        ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")

    return LocalStorageView(
        node_id=EDGE_NODE_ID,
        vault_version=metadata.get("vault_version"),
        ciphertext_b64=ciphertext_b64,
        integrity_hash=metadata.get("integrity_hash"),
        has_local_key=config.get_fernet_key_path(EDGE_NODE_ID).exists(),
    )


@app.get("/audit-log", response_model=AuditLogResponse)
def audit_log() -> AuditLogResponse:
    """Return the edge-node audit log entries."""
    return audit.read_audit_log(EDGE_NODE_ID)


def _get_edge_node_id() -> str:
    """Resolve the edge node identity from environment or default to edgeA."""
    candidate = os.getenv("EDGE_NODE_ID")
    if candidate:
        try:
            validated = config.validate_node_id(candidate)
        except ValueError as exc:
            raise RuntimeError(f"Invalid EDGE_NODE_ID: {candidate}") from exc
        if validated not in config.EDGE_NODE_IDS:
            raise RuntimeError("EDGE_NODE_ID must refer to an edge node")
        return validated

    port_text = os.getenv("PORT") or os.getenv("UVICORN_PORT")
    if port_text and port_text.isdigit():
        port = int(port_text)
        for node_id in config.EDGE_NODE_IDS:
            if config.get_node_port(node_id) == port:
                return node_id

    return config.EDGE_A


def _utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


def _cloud_base_url() -> str:
    """Build the local cloud service base URL from shared configuration."""
    return f"http://127.0.0.1:{config.get_node_port(config.CLOUD)}"


def _serialize_plaintext(payload: dict[str, Any]) -> bytes:
    """Serialize plaintext JSON deterministically before local encryption."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _serialize_signed_payload(payload: dict[str, object]) -> bytes:
    """Serialize signed request fields in the same canonical format as the cloud service."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_private_key():
    """Load the edge node's Ed25519 private key from disk."""
    try:
        return crypto_utils.load_private_key_from_file(config.get_private_key_path(EDGE_NODE_ID))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="Edge private key not found") from exc


def _load_public_key():
    """Load the edge node's Ed25519 public key from disk."""
    try:
        return crypto_utils.load_public_key_from_file(config.get_public_key_path(EDGE_NODE_ID))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="Edge public key not found") from exc


def _load_fernet_key() -> bytes:
    """Load the edge node's local Fernet key used for vault encryption."""
    try:
        return crypto_utils.load_fernet_key_from_file(config.get_fernet_key_path(EDGE_NODE_ID))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="Local encryption key not found") from exc


def _public_key_to_b64(public_key: Any) -> str:
    """Convert the PEM-loaded Ed25519 public key into raw base64 bytes for API use."""
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_key_bytes).decode("ascii")


def _next_vault_version() -> int:
    """Return the next local vault version based on stored metadata."""
    metadata = storage.load_local_vault_metadata(EDGE_NODE_ID) or {}
    current_version = metadata.get("vault_version")
    if isinstance(current_version, int) and current_version >= 1:
        return current_version + 1
    return 1


def _nonce_candidates() -> list[dict]:
    """Load and prune cached nonces for this edge node."""
    entries = storage.load_nonce_cache(EDGE_NODE_ID)
    pruned_entries = _prune_nonce_entries(entries)
    if pruned_entries != entries:
        storage.save_nonce_cache(EDGE_NODE_ID, pruned_entries)
    return pruned_entries


def _generate_nonce() -> str:
    """Generate a nonce that is not already present in the shared nonce cache."""
    existing_nonces = {entry.get("nonce") for entry in _nonce_candidates()}
    for _ in range(10):
        nonce = uuid4().hex
        if nonce not in existing_nonces:
            return nonce
    raise HTTPException(status_code=500, detail="Unable to generate a unique nonce")


def _prune_nonce_entries(entries: list[dict]) -> list[dict]:
    """Remove expired nonce entries using the shared replay window."""
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

    return valid_entries[-config.MAX_NONCE_CACHE_ENTRIES :]


def _sign_payload(message: bytes) -> str:
    """Sign a canonical payload and verify it against the local public key before use."""
    private_key = _load_private_key()
    signature = crypto_utils.sign_message(private_key, message)
    if not crypto_utils.verify_signature(_load_public_key(), message, signature):
        raise HTTPException(status_code=500, detail="Local signature verification failed")
    return base64.b64encode(signature).decode("ascii")


def _ensure_cloud_registration() -> RegisterNodeResponse:
    """Register this edge node with the cloud before backup operations."""
    timestamp = _utc_now()
    public_key_b64 = identity().public_key_b64
    nonce = _generate_nonce()
    payload = {
        "action": "register-node",
        "node_id": EDGE_NODE_ID,
        "public_key_b64": public_key_b64,
        "timestamp": timestamp.isoformat(),
        "nonce": nonce,
    }
    signed_request = RegisterNodeRequest(
        node_id=EDGE_NODE_ID,
        public_key_b64=public_key_b64,
        signature_b64=_sign_payload(_serialize_signed_payload(payload)),
        timestamp=timestamp,
        nonce=nonce,
    )
    response = _post_to_cloud("/register-node", signed_request.model_dump(mode="json"))
    registration = RegisterNodeResponse.model_validate(response)
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=config.CLOUD,
        action="register_node",
        status="success",
        details={"message": registration.message},
    )
    return registration


def _store_backup_in_cloud(
    vault_version: int,
    ciphertext_b64: str,
    integrity_hash: str,
) -> StoreBackupResponse:
    """Send locally encrypted ciphertext to the cloud using the shared signed format."""
    timestamp = _utc_now()
    nonce = _generate_nonce()
    payload = {
        "action": "store-backup",
        "node_id": EDGE_NODE_ID,
        "vault_version": vault_version,
        "ciphertext_b64": ciphertext_b64,
        "integrity_hash": integrity_hash,
        "timestamp": timestamp.isoformat(),
        "nonce": nonce,
    }
    signed_request = StoreBackupRequest(
        node_id=EDGE_NODE_ID,
        vault_version=vault_version,
        ciphertext_b64=ciphertext_b64,
        integrity_hash=integrity_hash,
        signature_b64=_sign_payload(_serialize_signed_payload(payload)),
        timestamp=timestamp,
        nonce=nonce,
    )
    response = _post_to_cloud("/store-backup", signed_request.model_dump(mode="json"))
    return StoreBackupResponse.model_validate(response)


def _retrieve_backup_from_cloud(request_reason: str) -> RetrieveBackupResponse:
    """Request the stored ciphertext from the cloud using the shared signed format."""
    timestamp = _utc_now()
    nonce = _generate_nonce()
    payload = {
        "action": "retrieve-backup",
        "node_id": EDGE_NODE_ID,
        "request_reason": request_reason,
        "timestamp": timestamp.isoformat(),
        "nonce": nonce,
    }
    signed_request = RetrieveBackupRequest(
        node_id=EDGE_NODE_ID,
        request_reason=request_reason,
        signature_b64=_sign_payload(_serialize_signed_payload(payload)),
        timestamp=timestamp,
        nonce=nonce,
    )
    response = _post_to_cloud("/retrieve-backup", signed_request.model_dump(mode="json"))
    return RetrieveBackupResponse.model_validate(response)


def _post_to_cloud(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST a JSON payload to the cloud service and return the decoded JSON response."""
    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(
        url=f"{_cloud_base_url()}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=10) as response:
            response_body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        detail = _extract_error_detail(exc)
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"path": path, "status_code": exc.code, "detail": detail},
        )
        raise HTTPException(status_code=exc.code, detail=detail) from exc
    except error.URLError as exc:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"path": path, "reason": "cloud unavailable"},
        )
        raise HTTPException(status_code=503, detail="Cloud service unavailable") from exc

    return json.loads(response_body)


def _extract_error_detail(exc: error.HTTPError) -> str:
    """Extract a FastAPI-style error detail from an upstream HTTP error response."""
    try:
        payload = json.loads(exc.read().decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "Cloud request failed"

    detail = payload.get("detail")
    if isinstance(detail, str):
        return detail
    return "Cloud request failed"


def _append_audit_event(
    actor: str,
    target: str,
    action: str,
    status: str,
    details: dict[str, object],
) -> None:
    """Append an audit event to this edge node's log."""
    audit.append_audit_event(
        EDGE_NODE_ID,
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


EDGE_NODE_ID = _get_edge_node_id()
