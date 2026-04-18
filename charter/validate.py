"""Charter YAML validator.

Checks structural conformance to aps.charter/v1. Does NOT verify the
operator signature — see hermes_aps.verifier for cryptographic checks.

Usage:
    python charter/validate.py path/to/charter.yaml
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

REQUIRED_TOP = {
    "schema_version",
    "charter_id",
    "issuer",
    "subject_agent",
    "issued_at",
    "not_before",
    "not_after",
    "scopes",
    "signature",
}
REQUIRED_SKILL_CREATION_AXES = {
    "allowed",
    "domains",
    "persistent",
    "max_modifications_per_window",
    "modification_window_seconds",
}
SUPPORTED_SCHEMA = "aps.charter/v1"


class CharterValidationError(Exception):
    pass


def validate(charter: dict[str, Any]) -> None:
    missing = REQUIRED_TOP - charter.keys()
    if missing:
        raise CharterValidationError(f"missing top-level fields: {sorted(missing)}")

    if charter["schema_version"] != SUPPORTED_SCHEMA:
        raise CharterValidationError(
            f"unsupported schema_version: {charter['schema_version']!r} "
            f"(expected {SUPPORTED_SCHEMA!r})"
        )

    scopes = charter["scopes"]
    if "skill_creation" not in scopes:
        raise CharterValidationError("scopes.skill_creation is required")

    sc = scopes["skill_creation"]
    missing_axes = REQUIRED_SKILL_CREATION_AXES - sc.keys()
    if missing_axes:
        raise CharterValidationError(
            f"scopes.skill_creation missing axes: {sorted(missing_axes)}"
        )

    if not isinstance(sc["allowed"], bool):
        raise CharterValidationError("skill_creation.allowed must be bool")
    if not isinstance(sc["domains"], list):
        raise CharterValidationError("skill_creation.domains must be list")
    if not isinstance(sc["persistent"], bool):
        raise CharterValidationError("skill_creation.persistent must be bool")
    if not isinstance(sc["max_modifications_per_window"], int):
        raise CharterValidationError(
            "skill_creation.max_modifications_per_window must be int"
        )
    if not isinstance(sc["modification_window_seconds"], int):
        raise CharterValidationError(
            "skill_creation.modification_window_seconds must be int"
        )

    if sc["allowed"] and not sc["domains"]:
        # Empty domain allowlist with allowed=true is a footgun — every
        # mutation would be denied regardless of intent.
        raise CharterValidationError(
            "skill_creation.allowed is true but domains is empty — "
            "no mutation can ever pass the allowlist"
        )

    sig = charter["signature"]
    for f in ("algorithm", "signer_key_id", "value"):
        if f not in sig:
            raise CharterValidationError(f"signature.{f} is required")
    if sig["algorithm"] != "Ed25519":
        raise CharterValidationError(
            f"unsupported signature algorithm: {sig['algorithm']!r} (expected Ed25519)"
        )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate.py <charter.yaml>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    with path.open() as f:
        charter = yaml.safe_load(f)
    try:
        validate(charter)
    except CharterValidationError as exc:
        print(f"INVALID {path}: {exc}", file=sys.stderr)
        return 1
    print(f"OK {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
