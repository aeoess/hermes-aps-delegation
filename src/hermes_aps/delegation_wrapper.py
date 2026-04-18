"""Delegation wrapper — the seam between Hermes events and APS receipts.

Hermes calls these wrappers when:
  - a new skill is created (`wrap_skill_creation`)
  - an existing skill is modified (`wrap_skill_creation`, with parent_hash)
  - the agent invokes a tool (`wrap_tool_call`)

Each wrapper:
  1. Evaluates the event against the operator's charter (policy decision).
  2. Produces an in-toto Decision Receipt (allow / deny / alert).
  3. Signs the receipt with the governance signer's Ed25519 key.
  4. Returns (decision, signed_envelope) so Hermes can act + log.

Hermes-specific hook points are stubbed. See the README and the
`# TODO[hermes-hook]:` markers in this file.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from nacl.signing import SigningKey

from .canonical import digest_of
from .skill_receipt import (
    ReceiptContext,
    SkillSubject,
    build_skill_receipt,
    sign_receipt,
)
from .tool_call_receipt import (
    ToolCallSubject,
    build_tool_call_receipt,
    sign_tool_call_receipt,
)
from .verifier import charter_root_digest


@dataclass
class GovernanceSession:
    """Per-process state threaded through the receipt chain.

    Holds the charter, the signing key, and the running sequence + last
    receipt digest. Hermes instantiates one of these per agent process.
    """

    charter: dict[str, Any]
    signing_key: SigningKey
    issuer_id: str
    policy_id: str = "hermes-aps-policy/v0.1"
    sequence: int = 0
    previous_receipt_digest: dict[str, str] | None = None
    modification_history: list[float] = field(default_factory=list)

    @property
    def delegation_chain_root(self) -> dict[str, str]:
        return charter_root_digest(self.charter)

    @property
    def policy_digest(self) -> dict[str, str]:
        return digest_of(self.charter["scopes"])

    def _next_ctx(self, extra_meta: dict[str, Any] | None = None) -> ReceiptContext:
        return ReceiptContext(
            issuer_id=self.issuer_id,
            policy_id=self.policy_id,
            policy_digest=self.policy_digest,
            delegation_chain_root=self.delegation_chain_root,
            previous_receipt_digest=self.previous_receipt_digest,
            sequence=self.sequence,
            metadata=extra_meta or {},
        )

    def _advance(self, envelope: dict[str, Any]) -> None:
        self.previous_receipt_digest = envelope["_digest"]
        self.sequence += 1


# --- Policy evaluation -------------------------------------------------------

@dataclass
class PolicyOutcome:
    decision: str  # "allow" | "deny" | "alert"
    reason: str


def evaluate_skill_creation(
    charter: dict[str, Any],
    domain: str,
    persistent: bool,
    history: list[float],
    now: float | None = None,
) -> PolicyOutcome:
    sc = charter["scopes"]["skill_creation"]
    if not sc["allowed"]:
        return PolicyOutcome("deny", "charter forbids all skill creation")
    if domain not in sc["domains"]:
        return PolicyOutcome(
            "deny",
            f"domain {domain!r} not in charter allowlist {sc['domains']!r}",
        )
    if persistent and not sc["persistent"]:
        return PolicyOutcome(
            "deny", "persistent skill requested but charter allows ephemeral only"
        )
    now = now if now is not None else time.time()
    window = sc["modification_window_seconds"]
    cap = sc["max_modifications_per_window"]
    recent = [t for t in history if now - t <= window]
    if len(recent) >= cap:
        return PolicyOutcome(
            "deny",
            f"rate limit: {len(recent)} mutations in last {window}s exceeds {cap}",
        )
    return PolicyOutcome("allow", "within charter envelope")


def evaluate_tool_call(charter: dict[str, Any], tool_name: str) -> PolicyOutcome:
    tc = charter["scopes"].get("tool_call", {})
    if tool_name in tc.get("denied_tools", []):
        return PolicyOutcome("deny", f"tool {tool_name!r} on charter deny list")
    allowed = tc.get("allowed_tools")
    if allowed is not None and tool_name not in allowed:
        return PolicyOutcome(
            "deny", f"tool {tool_name!r} not in charter allow list {allowed!r}"
        )
    return PolicyOutcome("allow", "within charter envelope")


# --- Wrappers (Hermes seam) --------------------------------------------------

def wrap_skill_creation(
    session: GovernanceSession,
    *,
    skill_id: str,
    skill_version_hash: str,
    domain: str,
    source_code: str,
    persistent: bool = False,
    parent_skill_version_hash: str | None = None,
    now: float | None = None,
) -> tuple[PolicyOutcome, dict[str, Any]]:
    """Hermes calls this on every skill-creation or skill-modification event.

    # TODO[hermes-hook]: register this as the callback Hermes invokes.
    # The exact event shape will be confirmed once Nous publishes the
    # plugin surface for hermes-agent. See README.

    Returns (outcome, signed_envelope). On deny, Hermes MUST refuse the
    mutation but the signed deny envelope is still emitted to the audit
    log so operators can see the blocked attempt.
    """
    outcome = evaluate_skill_creation(
        session.charter, domain, persistent, session.modification_history, now=now
    )
    subject = SkillSubject(
        skill_id=skill_id,
        skill_version_hash=skill_version_hash,
        domain=domain,
        parent_skill_version_hash=parent_skill_version_hash,
        persistent=persistent,
        source_digest=digest_of({"source": source_code}),
    )
    statement = build_skill_receipt(
        subject=subject,
        decision=outcome.decision,  # type: ignore[arg-type]
        reason=outcome.reason,
        ctx=session._next_ctx(),
        output={
            "event": "skill_creation_attempt",
            "skill_id": skill_id,
            "domain": domain,
            "persistent": persistent,
        },
        issued_at=now,
    )
    envelope = sign_receipt(statement, session.signing_key)
    session._advance(envelope)
    if outcome.decision == "allow":
        session.modification_history.append(now if now is not None else time.time())
    return outcome, envelope


def wrap_tool_call(
    session: GovernanceSession,
    *,
    skill_id: str,
    skill_version_hash: str,
    parent_skill_version_hash: str | None,
    tool_name: str,
    arguments: dict[str, Any],
    creator_agent_id: str,
    now: float | None = None,
) -> tuple[PolicyOutcome, dict[str, Any]]:
    """Hermes calls this immediately before invoking a tool.

    # TODO[hermes-hook]: register this as the pre-invocation hook.
    # If outcome.decision != "allow", Hermes MUST NOT invoke the tool.
    # The signed envelope is recorded either way.
    """
    outcome = evaluate_tool_call(session.charter, tool_name)
    subject = ToolCallSubject(
        skill_id=skill_id,
        skill_version_hash=skill_version_hash,
        parent_skill_version_hash=parent_skill_version_hash,
        tool_name=tool_name,
        arguments=arguments,
        creator_agent_id=creator_agent_id,
    )
    statement = build_tool_call_receipt(
        subject=subject,
        decision=outcome.decision,  # type: ignore[arg-type]
        reason=outcome.reason,
        ctx=session._next_ctx(),
        tool_output={
            "event": "tool_call_attempt",
            "tool": tool_name,
            "skill_id": skill_id,
        },
        issued_at=now,
    )
    envelope = sign_tool_call_receipt(statement, session.signing_key)
    session._advance(envelope)
    return outcome, envelope
