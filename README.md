> Archived 2026-09-02. Exploratory wiring against stubbed Hermes interfaces; never completed. Kept as a record.

# hermes-aps-delegation

Reference integration showing how a self-modifying agent (Nous Hermes) emits APS governance attestations around its skill-creation and tool-call events, conformant with the in-toto Decision Receipt predicate.

This repo is a worked example, not production glue. Hermes-side hook points are stubbed and documented as TODOs. See [Assumed Hermes interfaces](#assumed-hermes-interfaces).

## The three-artifact chain

```
[1] Charter (operator-signed root delegation)
        │  authorizes skill_creation within scoped axes
        ▼
[2] Skill-creation receipt (governance_attestation)
        │  signed by agent or governance signer
        │  decision: allow | deny | alert
        │  delegationChainRoot → digest of [1]
        ▼
[3] Tool-call receipt (per invocation)
        │  binds to skill_version_hash that produced the call
        │  parent_skill_version_hash links revision history
        │  previousReceiptDigest links the receipt chain
        ▼
   Auditor walks [3] → [2] → [1], verifies signatures, checks
   monotonic narrowing (no receipt grants more than its parent).
```

When Hermes attempts a skill mutation outside its charter (e.g. `domains: ["code-review"]` and Hermes tries to mutate a `data-export` skill), the wrapper produces a **signed deny receipt** and surfaces it to operator alerting. The deny is not silent — it is itself a chained, signed artifact.

## Three modules

| Module | Purpose | Source |
|---|---|---|
| Charter template | Operator-facing YAML schema for the root delegation. Defines `skill_creation` axes (`allowed`, `domains`, `persistent`, `max_modifications_per_window`, `modification_window_seconds`) plus standard APS scopes. | [`charter/`](charter/) |
| Skill-creation receipt signer | Wraps Hermes skill-creation events. Produces Ed25519-signed receipts with the `governance_attestation` predicate, conformant with in-toto Decision Receipt. Chains via `previousReceiptDigest` to the delegation root. | [`src/hermes_aps/skill_receipt.py`](src/hermes_aps/skill_receipt.py) |
| Tool-call receipt signer | Per-invocation receipts with `skill_version_hash` and `parent_skill_version_hash` binding. Each tool call is provably attributable to the exact skill revision that emitted it. | [`src/hermes_aps/tool_call_receipt.py`](src/hermes_aps/tool_call_receipt.py) |

The `delegation_wrapper.py` ties them together: it is the seam Hermes calls.

## Composition with in-toto Decision Receipt

Receipts emitted by this repo carry `predicateType: https://veritasacta.com/attestation/decision-receipt/v0.1` ([in-toto/attestation#549](https://github.com/in-toto/attestation/pull/549)).

The `delegationChainRoot` field (optional in the predicate, mandatory here) cross-references the governance attestation that binds agent authority. This is the bridge between APS's structural authority record and in-toto's per-decision attestation framework. Same schema, different perspectives.

## Composition with neighbor repos

| Repo | Owner | Role |
|---|---|---|
| `hermes-aps-delegation` | aeoess | governance attestations + delegation chain (this repo) |
| `hermes-decision-receipts` | tomjwxf | decision-receipt signing, broader scope |
| `hermes-audit-walker` | TBD | walks the full chain across both predicate sources |

The composition shape is committed in [NousResearch/hermes-agent#11692](https://github.com/NousResearch/hermes-agent/issues/11692).

## Quickstart

```bash
pip install -e ".[dev]"

# Generate operator keys + sign a charter
python examples/skill-mutation-allowed.py

# Watch a denied mutation produce a signed deny receipt
python examples/skill-mutation-denied.py

# Walk a 3-revision skill mutation chain
python examples/revision-chain.py
```

## Skill-creation axes

The charter scopes self-modification along five axes:

| Axis | Type | Meaning |
|---|---|---|
| `skill_creation.allowed` | bool | Master switch. `false` denies all skill mutations regardless of other axes. |
| `skill_creation.domains` | list[str] | Allowlist of domain tags. Skills outside the list cannot be created or mutated. |
| `skill_creation.persistent` | bool | Whether new skills survive process restart. `false` = ephemeral session-only skills. |
| `skill_creation.max_modifications_per_window` | int | Rate limit on mutations within `modification_window_seconds`. |
| `skill_creation.modification_window_seconds` | int | Sliding window for the rate limit. |

These axes compose with APS monotonic narrowing: a sub-delegation can shrink any axis but never widen. A child charter with `domains: ["code-review", "data-export"]` derived from a parent with `domains: ["code-review"]` is rejected at attestation time.

## Assumed Hermes interfaces

The wrapper assumes Hermes exposes these hook points. Each is marked with a `# TODO[hermes-hook]:` comment in the source.

```python
# Assumed Hermes API (subject to revision once integration is live)

class HermesAgent:
    def on_skill_creation(self, callback): ...
    def on_skill_modification(self, callback): ...
    def on_tool_call(self, callback): ...

class SkillCreationEvent:
    skill_id: str
    domain: str
    source_code: str
    parent_version_hash: str | None  # for revisions
    persistent: bool

class ToolCallEvent:
    skill_id: str
    skill_version_hash: str
    tool_name: str
    arguments: dict
```

When Nous publishes the actual hook surface, replace the stubs in `delegation_wrapper.py`. The receipt-signing code below the seam needs no changes.

## Status

- v0.1.0 target: end of April 2026 (coordinated with [NousResearch/hermes-agent#11692](https://github.com/NousResearch/hermes-agent/issues/11692))
- Predicate conformance: in-toto Decision Receipt `v0.1` ([#549](https://github.com/in-toto/attestation/pull/549))
- Cross-test status: TBD once tomjwxf's `hermes-decision-receipts` ships

## License

Apache-2.0. See [LICENSE](LICENSE).
