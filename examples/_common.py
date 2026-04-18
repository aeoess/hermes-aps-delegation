"""Helpers shared by the worked examples.

Loads a charter, generates an Ed25519 governance key, and assembles a
GovernanceSession + a TrustedKey map ready for the verifier.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from nacl.signing import SigningKey

from hermes_aps.delegation_wrapper import GovernanceSession
from hermes_aps.skill_receipt import _verify_key_id  # noqa: PLC2701  (intentional internal use)
from hermes_aps.verifier import TrustedKey

CHARTER_DIR = Path(__file__).resolve().parents[1] / "charter" / "examples"


def load_charter(name: str) -> dict:
    path = CHARTER_DIR / name
    with path.open() as f:
        return yaml.safe_load(f)


def fresh_session(
    charter: dict,
    issuer_id: str = "did:key:z6MkDemoGovernanceSigner000000000000000000000",
) -> tuple[GovernanceSession, dict[str, TrustedKey]]:
    signing_key = SigningKey.generate()
    keyid = _verify_key_id(signing_key)
    session = GovernanceSession(
        charter=charter, signing_key=signing_key, issuer_id=issuer_id
    )
    trusted = {keyid: TrustedKey(keyid=keyid, verify_key=signing_key.verify_key)}
    return session, trusted


def fake_skill_version(skill_id: str, revision: int) -> str:
    """Deterministic stand-in for a real content-addressed skill hash."""
    return hashlib.sha256(f"{skill_id}@rev{revision}".encode()).hexdigest()
