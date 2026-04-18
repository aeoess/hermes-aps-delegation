"""Worked example: 3-revision skill mutation chain + a tool call from the
final revision. Shows the full audit walk back to the operator charter.

Flow:
  rev1: skill created (parent_skill_version_hash = None)
  rev2: skill modified (parent_skill_version_hash = rev1)
  rev3: skill modified again (parent_skill_version_hash = rev2)
  call: tool invocation bound to rev3 (and via parent_skill_version_hash
        on the call receipt's metadata, transitively to rev2 and rev1)

Auditor walks the chain, verifies signatures, confirms the
delegationChainRoot is identical across all four envelopes, and that
narrowing holds at every step.
"""
from __future__ import annotations

from _common import fake_skill_version, fresh_session, load_charter

from hermes_aps.delegation_wrapper import wrap_skill_creation, wrap_tool_call
from hermes_aps.verifier import charter_root_digest, verify_chain


def main() -> int:
    charter = load_charter("moderate.yaml")
    session, trusted = fresh_session(charter)

    skill_id = "hermes.skill.code_review.v1"
    rev_hashes = [fake_skill_version(skill_id, r) for r in (1, 2, 3)]

    envelopes = []
    parent: str | None = None
    for idx, version_hash in enumerate(rev_hashes, start=1):
        outcome, env = wrap_skill_creation(
            session,
            skill_id=skill_id,
            skill_version_hash=version_hash,
            domain="code-review",
            source_code=f"# code-review skill, revision {idx}\n",
            persistent=True,
            parent_skill_version_hash=parent,
        )
        print(f"rev{idx}: {outcome.decision} ({outcome.reason})")
        assert outcome.decision == "allow"
        envelopes.append(env)
        parent = version_hash

    # Tool call attributed to the latest revision.
    outcome, env = wrap_tool_call(
        session,
        skill_id=skill_id,
        skill_version_hash=rev_hashes[-1],
        parent_skill_version_hash=rev_hashes[-2],
        tool_name="read_file",
        arguments={"path": "/workspace/repo/src/main.py"},
        creator_agent_id="did:key:z6MkHermesModerate0000000000000000000000000000",
    )
    print(f"tool call: {outcome.decision} ({outcome.reason})")
    assert outcome.decision == "allow"
    envelopes.append(env)

    verify_chain(
        envelopes=envelopes,
        charter=charter,
        delegation_chain_root=charter_root_digest(charter),
        trusted=trusted,
    )
    print(f"chain verified: {len(envelopes)} receipts back to charter root")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
