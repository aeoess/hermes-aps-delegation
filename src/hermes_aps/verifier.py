"""Receipt-chain verifier.

Walks a sequence of signed receipts back to the delegation root and
checks:
  1. Each signature is valid under the declared issuer key.
  2. The chain is contiguous: receipt[n].previousReceiptDigest matches
     the digest of the canonical payload of receipt[n-1].
  3. Every receipt's delegationChainRoot points to the same root
     (no chain-splicing across charters).
  4. Monotonic narrowing: no skill-creation receipt grants a domain
     outside the charter's allowlist; no tool call invokes a tool
     outside the charter's allowed_tools.

This is a worked-example verifier. A production verifier would also
check `not_before` / `not_after`, the signer's authority to issue
governance attestations for the subject agent, revocation status, and
clock skew.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .canonical import canonical_json, digest_of, digest_set


class ChainError(Exception):
    pass


@dataclass
class TrustedKey:
    keyid: str
    verify_key: VerifyKey


def _statement_from_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    return json.loads(envelope["payload"])


def verify_signature(envelope: dict[str, Any], trusted: dict[str, TrustedKey]) -> None:
    """Verify the DSSE-style envelope signature using a trusted-key map."""
    if not envelope.get("signatures"):
        raise ChainError("envelope has no signatures")
    sig_entry = envelope["signatures"][0]
    keyid = sig_entry["keyid"]
    if keyid not in trusted:
        raise ChainError(f"untrusted signer: {keyid}")
    payload = envelope["payload"].encode("utf-8")
    try:
        trusted[keyid].verify_key.verify(payload, bytes.fromhex(sig_entry["sig"]))
    except BadSignatureError as exc:
        raise ChainError(f"bad signature from {keyid}") from exc


def verify_chain(
    envelopes: list[dict[str, Any]],
    charter: dict[str, Any],
    delegation_chain_root: dict[str, str],
    trusted: dict[str, TrustedKey],
) -> None:
    """Verify a chain of receipts against a charter and trusted key set."""
    if not envelopes:
        raise ChainError("empty chain")

    expected_prev: dict[str, str] | None = None
    for idx, envelope in enumerate(envelopes):
        verify_signature(envelope, trusted)

        statement = _statement_from_envelope(envelope)
        pred = statement["predicate"]

        if pred["delegationChainRoot"] != delegation_chain_root:
            raise ChainError(
                f"receipt {idx}: delegationChainRoot mismatch "
                f"(got {pred['delegationChainRoot']}, expected {delegation_chain_root})"
            )

        if pred["previousReceiptDigest"] != expected_prev:
            raise ChainError(
                f"receipt {idx}: previousReceiptDigest break "
                f"(got {pred['previousReceiptDigest']}, expected {expected_prev})"
            )

        if pred["sequence"] != idx:
            raise ChainError(
                f"receipt {idx}: sequence mismatch (got {pred['sequence']})"
            )

        _check_narrowing(statement, charter)

        expected_prev = digest_set(envelope["payload"].encode("utf-8"))


def _check_narrowing(statement: dict[str, Any], charter: dict[str, Any]) -> None:
    """No receipt may grant authority broader than the charter."""
    pred = statement["predicate"]
    meta = pred["metadata"]
    scopes = charter["scopes"]

    kind = meta.get("receiptKind")
    if kind == "skill_creation":
        sc = scopes["skill_creation"]
        if pred["decision"] == "allow":
            if not sc["allowed"]:
                raise ChainError(
                    "skill_creation allowed but charter forbids all skill mutation"
                )
            domain = meta.get("domain")
            if domain not in sc["domains"]:
                raise ChainError(
                    f"skill_creation domain {domain!r} outside charter "
                    f"allowlist {sc['domains']!r}"
                )
            if meta.get("persistent") and not sc["persistent"]:
                raise ChainError(
                    "persistent skill creation but charter forbids persistence"
                )
    elif kind == "tool_call":
        tc = scopes.get("tool_call", {})
        if pred["decision"] == "allow":
            tool = meta.get("toolName")
            if tool in tc.get("denied_tools", []):
                raise ChainError(f"tool_call {tool!r} is on charter deny list")
            allowed = tc.get("allowed_tools")
            if allowed is not None and tool not in allowed:
                raise ChainError(
                    f"tool_call {tool!r} outside charter allow list {allowed!r}"
                )


def charter_root_digest(charter: dict[str, Any]) -> dict[str, str]:
    """Compute the canonical digest of a charter (excluding the signature
    field itself, which signs the rest). Used as delegationChainRoot."""
    body = {k: v for k, v in charter.items() if k != "signature"}
    return digest_of(body)


def derive_canonical_payload(envelope: dict[str, Any]) -> bytes:
    """Re-canonicalize the statement from the envelope payload string.
    Lets callers compare digests independently of the original signing run."""
    statement = _statement_from_envelope(envelope)
    return canonical_json(statement)
