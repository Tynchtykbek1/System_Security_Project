from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import ALLOWED_RECOVERY_REASONS, validate_node_id


def _validate_base64(value: str, field_name: str) -> str:
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field_name} must be valid base64") from exc
    return value


def _validate_utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be in UTC")
    return value


def _validate_recovery_reason(value: str) -> str:
    if value not in ALLOWED_RECOVERY_REASONS:
        allowed = ", ".join(ALLOWED_RECOVERY_REASONS)
        raise ValueError(f"request_reason must be one of: {allowed}")
    return value


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

    @field_validator("node_id")
    @classmethod
    def validate_node_id_field(cls, value: str) -> str:
        return validate_node_id(value)

    @field_validator("public_key_b64", "signature_b64")
    @classmethod
    def validate_base64_fields(cls, value: str, info: Any) -> str:
        return _validate_base64(value, info.field_name)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _validate_utc_timestamp(value)


class RegisterNodeResponse(BaseModel):
    registered: bool
    node_id: str
    message: str


class StoreBackupRequest(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=50)
    vault_version: int = Field(..., ge=1)
    ciphertext_b64: str = Field(..., min_length=32)
    integrity_hash: str = Field(..., min_length=64, max_length=64)
    timestamp: datetime
    nonce: str = Field(..., min_length=8, max_length=128)
    signature_b64: str = Field(..., min_length=32)

    @field_validator("node_id")
    @classmethod
    def validate_node_id_field(cls, value: str) -> str:
        return validate_node_id(value)

    @field_validator("ciphertext_b64", "signature_b64")
    @classmethod
    def validate_base64_fields(cls, value: str, info: Any) -> str:
        return _validate_base64(value, info.field_name)

    @field_validator("integrity_hash")
    @classmethod
    def validate_integrity_hash(cls, value: str) -> str:
        if len(value) != 64:
            raise ValueError("integrity_hash must be exactly 64 characters")
        if not all(ch in "0123456789abcdef" for ch in value):
            raise ValueError("integrity_hash must be exactly 64 lowercase hex characters")
        return value

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _validate_utc_timestamp(value)


class StoreBackupResponse(BaseModel):
    stored: bool
    node_id: str
    vault_version: int
    stored_at: datetime
    message: str


class RetrieveBackupRequest(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=50)
    request_reason: str
    timestamp: datetime
    nonce: str = Field(..., min_length=8, max_length=128)
    signature_b64: str = Field(..., min_length=32)

    @field_validator("node_id")
    @classmethod
    def validate_node_id_field(cls, value: str) -> str:
        return validate_node_id(value)

    @field_validator("request_reason")
    @classmethod
    def validate_request_reason(cls, value: str) -> str:
        return _validate_recovery_reason(value)

    @field_validator("signature_b64")
    @classmethod
    def validate_base64_fields(cls, value: str, info: Any) -> str:
        return _validate_base64(value, info.field_name)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _validate_utc_timestamp(value)


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
    recovered_plaintext: Optional[dict[str, Any]] = None
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
    details: dict[str, Any] = Field(default_factory=dict)


class AuditLogResponse(BaseModel):
    entries: list[AuditEvent]
