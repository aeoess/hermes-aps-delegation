"""Tool-call receipt signer.

Each tool invocation by Hermes is bound to:
  - the skill_id and skill_version_hash that emitted the call
  - the parent_skill_version_hash (if this skill is a revision)
  - the delegation_chain_root (operator charter digest)

This means an auditor can take any tool call and walk back through the
revision chain to the exact line of source that produced it, and from
there to the operator authorization that allowed the skill to exist.

Same predicate as skill_receipt.py (in-toto Decision Receipt v0.1) — the
distinction is in `metadata.receiptKind` and what's in the subject.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from nacl.signing import SigningKey

from . import PREDICATE_TYPE_DECISION_RECEIPT
from .canonical import canonical_json, digest_of, digest_set
from .skill_receipt import Decision, ReceiptContext, _iso8601, _verify_key_id


@dataclass
class ToolCallSubject:
    skill_id: str
    skill_version_hash: str
    parent_skill_version_hash: str | None
    tool_name: str
    arguments: dict[str, Any]
    creator_agent_id: str

    def to_intoto_subject(self) -> dict[str, Any]:
        # Subject digest binds the tool call to the skill version that
        # emitted it. Auditors index on this digest to find every call
        # produced by a given revision.
        return {
            "name": (
                f"hermes-tool-call:{self.tool_name}"
                f"@skill:{self.skill_id}@v:{self.skill_version_hash[:12]}"
            ),
            "digest": {"sha256": self.skill_version_hash},
        }


def build_tool_call_receipt(
    subject: ToolCallSubject,
    decision: Decision,
    reason: str,
    ctx: ReceiptContext,
    tool_output: dict[str, Any] | None = None,
    issued_at: float | None = None,
) -> dict[str, Any]:
    """Build an unsigned tool-call receipt envelope."""
    now = issued_at if issued_at is not None else time.time()
    output_payload = tool_output if tool_output is not None else {"event": "tool_call"}

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
                "receiptKind": "tool_call",
                "skillId": subject.skill_id,
                "skillVersionHash": subject.skill_version_hash,
                "parentSkillVersionHash": subject.parent_skill_version_hash,
                "toolName": subject.tool_name,
                "argumentsDigest": digest_of(subject.arguments),
                "creatorAgentId": subject.creator_agent_id,
                **ctx.metadata,
            },
        },
    }
    return statement


def sign_tool_call_receipt(
    statement: dict[str, Any], signing_key: SigningKey
) -> dict[str, Any]:
    """Same DSSE envelope as skill receipts — kept as a separate symbol
    so callers can intercept tool-call signing independently if needed."""
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
        "_digest": digest_set(payload),
    }
