"""Worked example: Hermes mutates a skill within its charter envelope.

Flow:
  1. Operator signs the moderate charter (skill_creation.allowed=true,
     domains=["code-review", "documentation", "test-generation"]).
  2. Hermes proposes a code-review skill mutation.
  3. Wrapper evaluates against charter -> allow.
  4. Signed receipt chains back to the charter root.
  5. Verifier walks the chain, validates the signature, confirms
     monotonic narrowing holds.
"""
from __future__ import annotations

from _common import fake_skill_version, fresh_session, load_charter

from hermes_aps.delegation_wrapper import wrap_skill_creation
from hermes_aps.verifier import charter_root_digest, verify_chain


def main() -> int:
    charter = load_charter("moderate.yaml")
    session, trusted = fresh_session(charter)

    outcome, envelope = wrap_skill_creation(
        session,
        skill_id="hermes.skill.code_review.v1",
        skill_version_hash=fake_skill_version("hermes.skill.code_review.v1", 1),
        domain="code-review",
        source_code="def review(diff):\n    return analyze(diff)\n",
        persistent=True,
    )

    print(f"decision: {outcome.decision} ({outcome.reason})")
    assert outcome.decision == "allow", outcome.reason

    verify_chain(
        envelopes=[envelope],
        charter=charter,
        delegation_chain_root=charter_root_digest(charter),
        trusted=trusted,
    )
    print("chain verified: receipt signature valid, narrowing holds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
