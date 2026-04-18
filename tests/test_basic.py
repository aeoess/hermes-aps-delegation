"""Smoke tests covering the wrapper, signing, and verifier loop."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
import yaml
from nacl.signing import SigningKey

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from hermes_aps.delegation_wrapper import (  # noqa: E402
    GovernanceSession,
    evaluate_skill_creation,
    evaluate_tool_call,
    wrap_skill_creation,
    wrap_tool_call,
)
from hermes_aps.skill_receipt import _verify_key_id  # noqa: E402
from hermes_aps.verifier import (  # noqa: E402
    ChainError,
    TrustedKey,
    charter_root_digest,
    verify_chain,
)


def _load(name: str) -> dict:
    with (REPO / "charter" / "examples" / name).open() as f:
        return yaml.safe_load(f)


def _session(charter: dict) -> tuple[GovernanceSession, dict[str, TrustedKey]]:
    sk = SigningKey.generate()
    keyid = _verify_key_id(sk)
    return (
        GovernanceSession(charter=charter, signing_key=sk, issuer_id="did:key:test"),
        {keyid: TrustedKey(keyid=keyid, verify_key=sk.verify_key)},
    )


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def test_strict_charter_denies_all_creation() -> None:
    outcome = evaluate_skill_creation(_load("strict.yaml"), "code-review", False, [])
    assert outcome.decision == "deny"


def test_moderate_charter_allows_listed_domain() -> None:
    outcome = evaluate_skill_creation(_load("moderate.yaml"), "code-review", True, [])
    assert outcome.decision == "allow"


def test_moderate_charter_denies_unlisted_domain() -> None:
    outcome = evaluate_skill_creation(_load("moderate.yaml"), "data-export", False, [])
    assert outcome.decision == "deny"
    assert "allowlist" in outcome.reason


def test_persistent_against_ephemeral_only_charter() -> None:
    outcome = evaluate_skill_creation(_load("permissive.yaml"), "research", True, [])
    assert outcome.decision == "deny"
    assert "ephemeral" in outcome.reason


def test_rate_limit_triggers_deny() -> None:
    charter = _load("permissive.yaml")
    cap = charter["scopes"]["skill_creation"]["max_modifications_per_window"]
    history = [0.0] * cap
    outcome = evaluate_skill_creation(charter, "research", False, history, now=1.0)
    assert outcome.decision == "deny"
    assert "rate limit" in outcome.reason


def test_tool_call_deny_list() -> None:
    outcome = evaluate_tool_call(_load("moderate.yaml"), "execute_shell")
    assert outcome.decision == "deny"


def test_tool_call_allow_list_miss() -> None:
    outcome = evaluate_tool_call(_load("moderate.yaml"), "fetch_url")
    assert outcome.decision == "deny"
    assert "allow list" in outcome.reason


def test_chain_verifies_for_allowed_revision() -> None:
    charter = _load("moderate.yaml")
    session, trusted = _session(charter)
    _, env = wrap_skill_creation(
        session,
        skill_id="s1",
        skill_version_hash=_hash("s1@1"),
        domain="code-review",
        source_code="x",
        persistent=True,
    )
    verify_chain([env], charter, charter_root_digest(charter), trusted)


def test_chain_breaks_when_signature_tampered() -> None:
    charter = _load("moderate.yaml")
    session, trusted = _session(charter)
    _, env = wrap_skill_creation(
        session,
        skill_id="s1",
        skill_version_hash=_hash("s1@1"),
        domain="code-review",
        source_code="x",
        persistent=True,
    )
    env["signatures"][0]["sig"] = "00" * 64
    with pytest.raises(ChainError, match="bad signature"):
        verify_chain([env], charter, charter_root_digest(charter), trusted)


def test_chain_breaks_when_payload_swapped() -> None:
    charter = _load("moderate.yaml")
    session, trusted = _session(charter)
    _, env = wrap_skill_creation(
        session,
        skill_id="s1",
        skill_version_hash=_hash("s1@1"),
        domain="code-review",
        source_code="x",
        persistent=True,
    )
    # Mutate the payload string — signature no longer matches.
    env["payload"] = env["payload"].replace("code-review", "data-export")
    with pytest.raises(ChainError):
        verify_chain([env], charter, charter_root_digest(charter), trusted)


def test_multi_receipt_chain_sequence_and_links() -> None:
    charter = _load("moderate.yaml")
    session, trusted = _session(charter)
    envelopes = []
    parent = None
    for r in range(1, 4):
        _, env = wrap_skill_creation(
            session,
            skill_id="s1",
            skill_version_hash=_hash(f"s1@{r}"),
            domain="code-review",
            source_code=f"v{r}",
            persistent=True,
            parent_skill_version_hash=parent,
        )
        envelopes.append(env)
        parent = _hash(f"s1@{r}")
    _, tc_env = wrap_tool_call(
        session,
        skill_id="s1",
        skill_version_hash=_hash("s1@3"),
        parent_skill_version_hash=_hash("s1@2"),
        tool_name="read_file",
        arguments={"path": "/x"},
        creator_agent_id="did:key:test",
    )
    envelopes.append(tc_env)
    verify_chain(envelopes, charter, charter_root_digest(charter), trusted)


def test_chain_break_on_reordered_receipts() -> None:
    charter = _load("moderate.yaml")
    session, trusted = _session(charter)
    envs = []
    parent = None
    for r in range(1, 3):
        _, env = wrap_skill_creation(
            session,
            skill_id="s1",
            skill_version_hash=_hash(f"s1@{r}"),
            domain="code-review",
            source_code=f"v{r}",
            persistent=True,
            parent_skill_version_hash=parent,
        )
        envs.append(env)
        parent = _hash(f"s1@{r}")
    with pytest.raises(ChainError, match="previousReceiptDigest|sequence"):
        verify_chain(list(reversed(envs)), charter, charter_root_digest(charter), trusted)
