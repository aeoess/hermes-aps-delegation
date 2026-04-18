"""Skill-creation receipt signer.

Wraps a Hermes skill-creation or skill-modification event in a signed
receipt conformant with the in-toto Decision Receipt predicate
(https://github.com/in-toto/attestation/pull/549).

Each receipt records:
  - the skill being created or mutated (subject)
  - the policy decision (allow / deny / alert) and reason
  - a cryptographic link back to the operator's charter (delegationChainRoot)
  - a cryptographic link to the previous receipt in the chain
    (previousReceiptDigest)

The wrapper code that produces these receipts lives in
delegation_wrapper.py. This module is the signing primitive.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

from nacl.signing import SigningKey

from . import PREDICATE_TYPE_DECISION_RECEIPT
from .canonical import canonical_json, digest_of, digest_set


Decision = Literal["allow", "deny", "alert"]


@dataclass
class SkillSubject:
    """The skill-creation or skill-modification event being attested."""

    skill_id: str
    skill_version_hash: str
    domain: str
    parent_skill_version_hash: str | None = None
    persistent: bool = False
    source_digest: dict[str, str] | None = None  # DigestSet of source code

    def to_intoto_subject(self) -> dict[str, Any]:
        return {
            "name": f"hermes-skill:{self.skill_id}@{self.skill_version_hash[:12]}",
            "digest": {"sha256": self.skill_version_hash},
        }


@dataclass
class ReceiptContext:
    """Runtime context threaded through a session of receipts."""

    issuer_id: str
    policy_id: str
    policy_digest: dict[str, str]
    delegation_chain_root: dict[str, str]
    previous_receipt_digest: dict[str, str] | None = None
    sequence: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


def build_skill_receipt(
    subject: SkillSubject,
    decision: Decision,
    reason: str,
    ctx: ReceiptContext,
    output: dict[str, Any] | None = None,
    issued_at: float | None = None,
) -> dict[str, Any]:
    """Build an unsigned skill-creation receipt envelope.

    The returned dict is the in-toto Statement; sign_receipt produces the
    DSSE-style signature envelope on top.
    """
    now = issued_at if issued_at is not None else time.time()
    output_payload = output if output is not None else {"event": "skill_creation"}

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": PREDICATE_TYPE_DECISION_RECEIPT,
        "subject": [subject.to_intoto_subject()],
        "predicate": {
            "decision": decision,
            "reason": reason,
            "policyId": ctx.policy_id,
            "policyDigest": ctx.policy_digest,
            "issuedAt": _iso8601(now),
            "sequence": ctx.sequence,
            "previousReceiptDigest": ctx.previous_receipt_digest,
            "issuerId": ctx.issuer_id,
            "outputDigest": digest_of(output_payload),
            "delegationChainRoot": ctx.delegation_chain_root,
            "metadata": {
                "framework": "nous-hermes",
                "receiptKind": "skill_creation",
                "skillId": subject.skill_id,
                "skillVersionHash": subject.skill_version_hash,
                "parentSkillVersionHash": subject.parent_skill_version_hash,
                "domain": subject.domain,
                "persistent": subject.persistent,
                **ctx.metadata,
            },
        },
    }
    return statement


def sign_receipt(statement: dict[str, Any], signing_key: SigningKey) -> dict[str, Any]:
    """Sign a receipt statement and return the DSSE-style envelope."""
    payload = canonical_json(statement)
    sig = signing_key.sign(payload).signature
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": payload.decode("utf-8"),
        "signatures": [
            {
                "keyid": _verify_key_id(signing_key),
                "sig": sig.hex(),
            }
        ],
        # Convenience field — not part of DSSE, used for chain linking.
        "_digest": digest_set(payload),
    }


def _verify_key_id(signing_key: SigningKey) -> str:
    return f"ed25519:{signing_key.verify_key.encode().hex()[:16]}"


def _iso8601(epoch: float) -> str:
    import datetime as dt

    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
