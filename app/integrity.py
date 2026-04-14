from __future__ import annotations

import hashlib
from pathlib import Path
from secrets import compare_digest


def compute_sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest for an in-memory bytes payload."""
    # Hash raw bytes directly so callers can verify messages or serialized data.
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(file_path: str | Path) -> str:
    """Return the SHA-256 hex digest for a file on disk."""
    path = Path(file_path)
    hasher = hashlib.sha256()

    # Read the file in chunks to avoid loading large files into memory at once.
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(8192), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def hashes_match(expected_hash: str, actual_hash: str) -> bool:
    """Safely compare two hexadecimal hash strings."""
    # Normalize case and surrounding whitespace before constant-time comparison.
    normalized_expected = expected_hash.strip().lower()
    normalized_actual = actual_hash.strip().lower()
    return compare_digest(normalized_expected, normalized_actual)
