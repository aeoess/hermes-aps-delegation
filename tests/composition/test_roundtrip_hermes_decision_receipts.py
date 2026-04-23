"""Round-trip composition test: APS delegation envelope x hermes-decision-receipts.

Exercises the two-sided governance story committed in
NousResearch/hermes-agent#11692 between aeoess/hermes-aps-delegation (this repo,
delegation + charter enforcement) and ScopeBlind/hermes-decision-receipts
(tomjwxf, per-tool-call receipts).

Goal: an auditor holding only the two signed artifacts — one APS envelope and
one tool-call receipt — plus the two public keys can validate the full
"authority + decision" trace end-to-end offline. No aeoess server, no
ScopeBlind server, no network.

Tom's repo isn't on PyPI yet (v0.1.0 target end of April 2026). The receipt
signer on his side is therefore mocked locally. The mock matches the canonical
field set from ScopeBlind/hermes-decision-receipts' signer.py at clone time:
the envelope shape ``{payload, signature: {alg, kid, sig}}``, JCS
canonicalization, Ed25519 signatures, and the ``delegation_chain_root`` field
that cross-references the APS side. See docs/ROUNDTRIP-TEST-NOTES.md.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from hermes_aps import PREDICATE_TYPE_DECISION_RECEIPT  # noqa: E402
from hermes_aps.canonical import canonical_json, digest_of  # noqa: E402
from hermes_aps.delegation_wrapper import (  # noqa: E402
    GovernanceSession,
    wrap_skill_creation,
)
from hermes_aps.skill_receipt import _verify_key_id  # noqa: E402
from hermes_aps.verifier import (  # noqa: E402
    ChainError,
    TrustedKey,
    charter_root_digest,
    verify_chain,
)


# ---- Mock of ScopeBlind/hermes-decision-receipts ReceiptSigner --------------
#
# Mirrors the canonical shape in src/hermes_decision_receipts/signer.py at
# the time of this test. Fields preserved verbatim:
#   type, tool_name, tool_input_hash, decision, issued_at, issuer_id,
#   agent_id, session_id, sequence, previousReceiptHash, policy_id,
#   policy_hash, skill_version_hash, delegation_chain_root.
# Envelope shape preserved: {payload, signature: {alg, kid, sig}}.
# Canonicalization: JCS (RFC 8785) sorted-key compact JSON, UTF-8 bytes.
#
# Deliberate addition for cross-repo alignment (documented in the notes):
# ``predicateType`` is set to the in-toto Decision Receipt v0.1 URI so the
# two repos carry a shared predicate identifier. Tom's v0.1.0-alpha.1 still
# uses ``spec: draft-farley-acta-signed-receipts-01``; this field is the
# bridge the bilateral-receipt predicate spec will formalize.


def _jcs(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class MockReceipt:
    payload: dict[str, Any]
    signature: dict[str, str]
    receipt_id: str

    def to_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": self.signature}

    def verify(self, public_key_hex: str) -> bool:
        try:
            VerifyKey(bytes.fromhex(public_key_hex)).verify(
                _jcs(self.payload), bytes.fromhex(self.signature["sig"])
            )
            return True
        except BadSignatureError:
            return False


class MockHermesDecisionReceiptSigner:
    """Mirror of ScopeBlind/hermes-decision-receipts ReceiptSigner."""

    def __init__(
        self,
        signing_key: SigningKey,
        issuer: str = "hermes-decision-receipts",
        agent_id: str = "hermes-research-01",
    ) -> None:
        self._key = signing_key
        self._issuer = issuer
        self._agent_id = agent_id
        self._session_id = f"sess_{os.urandom(6).hex()}"
        self._sequence = 0
        self._last_hash: str | None = None

    @classmethod
    def generate(cls, **kwargs: Any) -> MockHermesDecisionReceiptSigner:
        return cls(SigningKey.generate(), **kwargs)

    @property
    def public_key_hex(self) -> str:
        return self._key.verify_key.encode().hex()

    @property
    def kid(self) -> str:
        return f"sb:hermes:{self.public_key_hex[:12]}"

    def sign_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any],
        decision: str = "allow",
        policy_id: str | None = None,
        policy_hash: str | None = None,
        skill_version_hash: str | None = None,
        delegation_chain_root: str | None = None,
    ) -> MockReceipt:
        if decision not in {"allow", "deny", "require_approval", "compensated"}:
            raise ValueError(f"invalid decision: {decision!r}")

        args_bytes = json.dumps(
            tool_args, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        tool_input_hash = _sha256_prefixed(args_bytes)

        payload: dict[str, Any] = {
            "type": "hermes:decision",
            "spec": "draft-farley-acta-signed-receipts-01",
            "predicateType": PREDICATE_TYPE_DECISION_RECEIPT,
            "tool_name": tool_name,
            "tool_input_hash": tool_input_hash,
            "decision": decision,
            "issued_at": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "issuer_id": self._issuer,
            "agent_id": self._agent_id,
            "session_id": self._session_id,
            "sequence": self._sequence + 1,
            "previousReceiptHash": self._last_hash,
        }
        if policy_id is not None:
            payload["policy_id"] = policy_id
        if policy_hash is not None:
            payload["policy_hash"] = policy_hash
        if skill_version_hash is not None:
            payload["skill_version_hash"] = skill_version_hash
        if delegation_chain_root is not None:
            payload["delegation_chain_root"] = delegation_chain_root

        canonical = _jcs(payload)
        sig = self._key.sign(canonical).signature
        receipt_id = _sha256_prefixed(canonical)
        self._sequence += 1
        self._last_hash = receipt_id

        return MockReceipt(
            payload=payload,
            signature={"alg": "EdDSA", "kid": self.kid, "sig": sig.hex()},
            receipt_id=receipt_id,
        )


# ---- Offline cross-side verification ---------------------------------------


def _aps_charter_root_as_prefixed_string(charter: dict[str, Any]) -> str:
    """Convert APS DigestSet {"sha256": hex} -> Tom's "sha256:hex" string."""
    digest_set = charter_root_digest(charter)
    return f"sha256:{digest_set['sha256']}"


def _verify_receipt_references_aps(
    receipt: MockReceipt,
    aps_envelope: dict[str, Any],
    receipt_public_key_hex: str,
) -> None:
    """Offline check that the Tom-side receipt is valid AND cross-links to APS."""
    if not receipt.verify(receipt_public_key_hex):
        raise ChainError("decision receipt signature failed verification")

    if receipt.payload.get("predicateType") != PREDICATE_TYPE_DECISION_RECEIPT:
        raise ChainError(
            f"predicateType mismatch: got {receipt.payload.get('predicateType')!r}, "
            f"expected {PREDICATE_TYPE_DECISION_RECEIPT!r}"
        )

    statement = json.loads(aps_envelope["payload"])
    aps_root = statement["predicate"]["delegationChainRoot"]
    expected_prefixed = f"sha256:{aps_root['sha256']}"

    if receipt.payload.get("delegation_chain_root") != expected_prefixed:
        raise ChainError(
            "delegation_chain_root mismatch: receipt references "
            f"{receipt.payload.get('delegation_chain_root')!r} but APS envelope "
            f"carries {expected_prefixed!r}"
        )


# ---- Fixtures ---------------------------------------------------------------


def _load_charter(name: str = "moderate.yaml") -> dict[str, Any]:
    with (REPO / "charter" / "examples" / name).open() as f:
        return yaml.safe_load(f)


@pytest.fixture
def charter() -> dict[str, Any]:
    return _load_charter()


@pytest.fixture
def aps_session_and_trust(charter: dict[str, Any]) -> tuple[GovernanceSession, dict[str, TrustedKey]]:
    sk = SigningKey.generate()
    keyid = _verify_key_id(sk)
    session = GovernanceSession(
        charter=charter,
        signing_key=sk,
        issuer_id="did:key:z6MkTestOperatorRoundtrip0000000000000000000",
    )
    return session, {keyid: TrustedKey(keyid=keyid, verify_key=sk.verify_key)}


# ---- Tests ------------------------------------------------------------------


def test_roundtrip_positive(
    charter: dict[str, Any],
    aps_session_and_trust: tuple[GovernanceSession, dict[str, TrustedKey]],
) -> None:
    """Positive round-trip: APS envelope + Tom-side receipt, both verify offline,
    and the auditor can confirm the cross-side link."""
    session, trusted = aps_session_and_trust

    # (a) APS side: emit the delegation envelope that authorizes a skill.
    skill_version_hash = hashlib.sha256(b"skill:code-review@v1").hexdigest()
    outcome, aps_envelope = wrap_skill_creation(
        session,
        skill_id="code-review-assist",
        skill_version_hash=skill_version_hash,
        domain="code-review",
        source_code="def review(diff): ...",
        persistent=True,
    )
    assert outcome.decision == "allow"

    # (b) Tom side: emit a tool-call receipt referencing the APS root.
    aps_root_string = _aps_charter_root_as_prefixed_string(charter)
    tom_signer = MockHermesDecisionReceiptSigner.generate(agent_id="hermes-research-01")
    tom_receipt = tom_signer.sign_tool_call(
        tool_name="read_file",
        tool_args={"path": "/workspace/repo/src/lib.py"},
        decision="allow",
        policy_id="research-read-only-v1",
        policy_hash=_sha256_prefixed(b"research-read-only-v1"),
        skill_version_hash=f"sha256:{skill_version_hash}",
        delegation_chain_root=aps_root_string,
    )

    # (c) Verify APS side: signature, monotonic narrowing, charter link.
    verify_chain(
        [aps_envelope],
        charter,
        charter_root_digest(charter),
        trusted,
    )

    # (d) Verify Tom side: signature, predicateType, delegation_chain_root link.
    _verify_receipt_references_aps(tom_receipt, aps_envelope, tom_signer.public_key_hex)

    # (e) Auditor assertion: only the two artifacts + two public keys are needed.
    #     No references to `session`, `trusted` dicts, or charter object beyond
    #     the charter file itself (which is the root document by construction).
    audit_inputs = {
        "aps_envelope": aps_envelope,
        "decision_receipt": tom_receipt.to_dict(),
        "aps_signer_public_key_hex": session.signing_key.verify_key.encode().hex(),
        "receipt_signer_public_key_hex": tom_signer.public_key_hex,
        "charter": charter,
    }
    _auditor_walk(audit_inputs)


def test_roundtrip_tamper_aps_scope_breaks_link(
    aps_session_and_trust: tuple[GovernanceSession, dict[str, TrustedKey]],
) -> None:
    """Negative: mutate a scope field in the charter AFTER the receipt was
    issued. Recomputing the APS root no longer matches the receipt's
    delegation_chain_root. Cross-side verification must fail with a clear
    error; APS-side chain verification independently must also fail."""
    session, trusted = aps_session_and_trust
    original_charter = session.charter
    original_root_string = _aps_charter_root_as_prefixed_string(original_charter)

    skill_version_hash = hashlib.sha256(b"skill:code-review@v1").hexdigest()
    _, aps_envelope = wrap_skill_creation(
        session,
        skill_id="code-review-assist",
        skill_version_hash=skill_version_hash,
        domain="code-review",
        source_code="def review(diff): ...",
        persistent=True,
    )

    tom_signer = MockHermesDecisionReceiptSigner.generate()
    tom_receipt = tom_signer.sign_tool_call(
        tool_name="read_file",
        tool_args={"path": "/workspace/repo/src/lib.py"},
        decision="allow",
        policy_id="research-read-only-v1",
        skill_version_hash=f"sha256:{skill_version_hash}",
        delegation_chain_root=original_root_string,
    )

    # Mutate the charter: widen the allowed domains. The re-hashed root changes.
    mutated_charter = json.loads(json.dumps(original_charter))  # deep copy via JSON
    mutated_charter["scopes"]["skill_creation"]["domains"].append("data-export")
    mutated_root_string = _aps_charter_root_as_prefixed_string(mutated_charter)
    assert mutated_root_string != original_root_string, (
        "sanity: mutating the charter must change its root digest"
    )

    # Rebuild a fresh APS envelope under the MUTATED charter so we have an
    # artifact whose delegationChainRoot is the mutated root. The Tom-side
    # receipt still points at the ORIGINAL root, so the cross-link breaks.
    mutated_session = GovernanceSession(
        charter=mutated_charter,
        signing_key=session.signing_key,
        issuer_id=session.issuer_id,
    )
    _, mutated_aps_envelope = wrap_skill_creation(
        mutated_session,
        skill_id="code-review-assist",
        skill_version_hash=skill_version_hash,
        domain="code-review",
        source_code="def review(diff): ...",
        persistent=True,
    )

    # Cross-side: receipt references old root, APS envelope references new root
    # -> link fails with a clear error.
    with pytest.raises(ChainError, match="delegation_chain_root mismatch"):
        _verify_receipt_references_aps(
            tom_receipt, mutated_aps_envelope, tom_signer.public_key_hex
        )

    # Belt-and-braces: the original APS envelope won't verify against the
    # mutated charter either (delegationChainRoot differs from recomputed).
    with pytest.raises(ChainError, match="delegationChainRoot mismatch"):
        verify_chain(
            [aps_envelope],
            mutated_charter,
            charter_root_digest(mutated_charter),
            trusted,
        )


def test_roundtrip_tamper_receipt_payload_breaks_signature(
    charter: dict[str, Any],
    aps_session_and_trust: tuple[GovernanceSession, dict[str, TrustedKey]],
) -> None:
    """Extra negative: flipping a bit inside the receipt payload invalidates
    the Ed25519 signature. Confirms the canonical shape we're mocking is
    actually being enforced."""
    session, _ = aps_session_and_trust
    _, _ = wrap_skill_creation(
        session,
        skill_id="code-review-assist",
        skill_version_hash=hashlib.sha256(b"skill:code-review@v1").hexdigest(),
        domain="code-review",
        source_code="def review(diff): ...",
        persistent=True,
    )

    tom_signer = MockHermesDecisionReceiptSigner.generate()
    receipt = tom_signer.sign_tool_call(
        tool_name="read_file",
        tool_args={"path": "/workspace/repo/src/lib.py"},
        decision="allow",
        delegation_chain_root=_aps_charter_root_as_prefixed_string(charter),
    )
    assert receipt.verify(tom_signer.public_key_hex)

    receipt.payload["decision"] = "deny"
    assert not receipt.verify(tom_signer.public_key_hex)


# ---- Auditor walker ---------------------------------------------------------


def _auditor_walk(inputs: dict[str, Any]) -> None:
    """Third-party auditor: no server access, no network, no fixture state.
    Given exactly these five inputs, the auditor must be able to validate
    the authority-plus-decision trace end-to-end.
    """
    aps_env = inputs["aps_envelope"]
    receipt_dict = inputs["decision_receipt"]
    aps_pub_hex = inputs["aps_signer_public_key_hex"]
    receipt_pub_hex = inputs["receipt_signer_public_key_hex"]
    charter = inputs["charter"]

    # 1. APS signature.
    VerifyKey(bytes.fromhex(aps_pub_hex)).verify(
        aps_env["payload"].encode("utf-8"),
        bytes.fromhex(aps_env["signatures"][0]["sig"]),
    )

    # 2. APS statement integrity: re-canonicalizing the statement must match
    #    the signed payload bytes.
    statement = json.loads(aps_env["payload"])
    assert canonical_json(statement) == aps_env["payload"].encode("utf-8")
    assert statement["predicateType"] == PREDICATE_TYPE_DECISION_RECEIPT

    # 3. APS delegationChainRoot matches the recomputed charter digest.
    expected_root = charter_root_digest(charter)
    assert statement["predicate"]["delegationChainRoot"] == expected_root

    # 4. Receipt signature.
    payload = receipt_dict["payload"]
    sig = receipt_dict["signature"]
    VerifyKey(bytes.fromhex(receipt_pub_hex)).verify(
        _jcs(payload), bytes.fromhex(sig["sig"])
    )

    # 5. Shared predicateType.
    assert payload["predicateType"] == PREDICATE_TYPE_DECISION_RECEIPT

    # 6. Cross-side link: receipt.delegation_chain_root ==
    #    "sha256:" + APS envelope's delegationChainRoot.sha256.
    assert payload["delegation_chain_root"] == f"sha256:{expected_root['sha256']}"

    # 7. Charter narrowing: the APS decision must itself be within the
    #    charter's skill_creation.domains.
    sc = charter["scopes"]["skill_creation"]
    assert statement["predicate"]["metadata"]["domain"] in sc["domains"]
    assert sc["allowed"] is True

    # At this point the auditor has verified, offline:
    #   - both signatures
    #   - the APS envelope's in-toto wrapping is consistent
    #   - the charter digest cross-references
    #   - the receipt's predicateType matches
    #   - the charter's narrowing is respected
