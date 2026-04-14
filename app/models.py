from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str
    node_id: str


class IdentityResponse(BaseModel):
    node_id: str
    public_key_b64: str


class RegisterNodeRequest(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=50)
    public_key_b64: str = Field(..., min_length=32)
    signature_b64: str = Field(..., min_length=32)
    timestamp: datetime
    nonce: str = Field(..., min_length=8, max_length=128)


class RegisterNodeResponse(BaseModel):
    registered: bool
    node_id: str
    message: str


class StoreBackupRequest(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=50)
    vault_version: int = Field(..., ge=1)
    ciphertext_b64: str = Field(..., min_length=32)
    integrity_hash: str = Field(..., min_length=32, max_length=128)
    timestamp: datetime
    nonce: str = Field(..., min_length=8, max_length=128)
    signature_b64: str = Field(..., min_length=32)

    @field_validator("integrity_hash")
    @classmethod
    def validate_integrity_hash(cls, value: str) -> str:
        value = value.strip().lower()
        if not all(ch in "0123456789abcdef" for ch in value):
            raise ValueError("integrity_hash must be a lowercase hex string")
        return value


class StoreBackupResponse(BaseModel):
    stored: bool
    node_id: str
    vault_version: int
    stored_at: datetime
    message: str


class RetrieveBackupRequest(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=50)
    request_reason: Literal["recovery", "sync", "audit"]
    timestamp: datetime
    nonce: str = Field(..., min_length=8, max_length=128)
    signature_b64: str = Field(..., min_length=32)


class RetrieveBackupResponse(BaseModel):
    found: bool
    node_id: str
    vault_version: Optional[int] = None
    ciphertext_b64: Optional[str] = None
    integrity_hash: Optional[str] = None
    stored_at: Optional[datetime] = None
    message: str


class EncryptAndBackupResponse(BaseModel):
    success: bool
    node_id: str
    vault_version: int
    message: str


class RecoverFromCloudResponse(BaseModel):
    success: bool
    node_id: str
    vault_version: Optional[int] = None
    recovered_plaintext: Optional[dict] = None
    message: str


class LocalStorageView(BaseModel):
    node_id: str
    vault_version: Optional[int] = None
    ciphertext_b64: Optional[str] = None
    integrity_hash: Optional[str] = None
    has_local_key: bool


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    actor: str
    target: str
    action: Literal[
        "register_node",
        "store_backup",
        "retrieve_backup",
        "encrypt_local",
        "decrypt_local",
        "replay_rejected",
        "signature_rejected",
        "integrity_mismatch",
        "request_denied",
    ]
    status: Literal["success", "failure"]
    timestamp: datetime
    details: dict = Field(default_factory=dict)


class AuditLogResponse(BaseModel):
    entries: list[AuditEvent]