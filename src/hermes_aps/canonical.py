"""Canonical JSON serialization + SHA-256 digests.

Receipts are signed over the canonical bytes. Any deviation in encoding
produces a different signature; verifiers re-canonicalize before checking.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """RFC 8785-style canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    """Hex-encoded SHA-256."""
    return hashlib.sha256(data).hexdigest()


def digest_set(data: bytes) -> dict[str, str]:
    """in-toto DigestSet: {algorithm: hex_digest}."""
    return {"sha256": sha256_digest(data)}


def digest_of(obj: Any) -> dict[str, str]:
    """DigestSet over the canonical JSON of obj."""
    return digest_set(canonical_json(obj))
