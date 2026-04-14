from __future__ import annotations

import json
from json import JSONDecodeError

from app.config import get_audit_log_path
from app.models import AuditEvent, AuditLogResponse


def _load_audit_entries(node_id: str) -> list[dict]:
    """Load audit entries, quarantining malformed JSON when necessary."""
    audit_log_path = get_audit_log_path(node_id)

    try:
        entries = json.loads(audit_log_path.read_text(encoding="utf-8"))
    except JSONDecodeError:
        corrupt_path = audit_log_path.with_suffix(f"{audit_log_path.suffix}.corrupt")
        audit_log_path.replace(corrupt_path)
        audit_log_path.write_text("[]", encoding="utf-8")
        return []

    if not isinstance(entries, list):
        corrupt_path = audit_log_path.with_suffix(f"{audit_log_path.suffix}.corrupt")
        audit_log_path.replace(corrupt_path)
        audit_log_path.write_text("[]", encoding="utf-8")
        return []

    return entries


def _write_audit_entries(node_id: str, entries: list[dict]) -> None:
    """Persist audit entries via temp file and atomic replace."""
    audit_log_path = get_audit_log_path(node_id)
    temp_path = audit_log_path.with_suffix(f"{audit_log_path.suffix}.tmp")
    temp_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    temp_path.replace(audit_log_path)


def ensure_audit_log_exists(node_id: str) -> None:
    """Create the audit log file and parent directories when missing."""
    audit_log_path = get_audit_log_path(node_id)
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    if not audit_log_path.exists():
        audit_log_path.write_text("[]", encoding="utf-8")


def append_audit_event(node_id: str, event: AuditEvent) -> None:
    """Append a validated audit event to the node's JSON audit log."""
    ensure_audit_log_exists(node_id)

    entries = _load_audit_entries(node_id)
    entries.append(event.model_dump(mode="json"))

    # Rewrite the full JSON array to keep the on-disk format simple.
    _write_audit_entries(node_id, entries)


def read_audit_log(node_id: str) -> AuditLogResponse:
    """Read and validate the node's audit log from disk."""
    ensure_audit_log_exists(node_id)

    entries = _load_audit_entries(node_id)

    # Validate stored entries against the shared response model.
    return AuditLogResponse(entries=[AuditEvent.model_validate(entry) for entry in entries])
