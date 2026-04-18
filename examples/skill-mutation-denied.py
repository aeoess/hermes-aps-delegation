"""Worked example: Hermes attempts a mutation outside its charter.

Flow:
  1. Operator signs the moderate charter (domains=["code-review",
     "documentation", "test-generation"]).
  2. Hermes attempts to mutate a `data-export` skill.
  3. Wrapper denies. The deny is itself a signed receipt — operators
     see every blocked attempt in the audit log.
  4. Verifier confirms the deny envelope is valid and chain-linked.
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
        skill_id="hermes.skill.data_export.v1",
        skill_version_hash=fake_skill_version("hermes.skill.data_export.v1", 1),
        domain="data-export",  # NOT in charter allowlist
        source_code="def export(rows):\n    return upload(rows)\n",
        persistent=False,
    )

    print(f"decision: {outcome.decision} ({outcome.reason})")
    assert outcome.decision == "deny", "expected deny — domain outside allowlist"

    verify_chain(
        envelopes=[envelope],
        charter=charter,
        delegation_chain_root=charter_root_digest(charter),
        trusted=trusted,
    )
    print("chain verified: signed deny is well-formed and operator-visible")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
