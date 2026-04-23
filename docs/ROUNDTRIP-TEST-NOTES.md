# Round-trip composition test notes

Companion notes for `tests/composition/test_roundtrip_hermes_decision_receipts.py`.
Exercises the two-sided governance story committed in
[NousResearch/hermes-agent#11692](https://github.com/NousResearch/hermes-agent/issues/11692):
this repo on the delegation/charter side,
[ScopeBlind/hermes-decision-receipts](https://github.com/ScopeBlind/hermes-decision-receipts)
on the per-tool-call decision side.

## What the test proves

An auditor holding exactly two signed artifacts and the two public keys that
produced them can, offline, validate the full "authority + decision" trace
end-to-end. No aeoess server, no ScopeBlind server, no network calls at any
step.

Concretely:

1. The APS side emits a signed in-toto Decision Receipt v0.1 envelope
   (`predicateType: https://veritasacta.com/attestation/decision-receipt/v0.1`)
   whose `predicate.delegationChainRoot` is the SHA-256 digest of the
   operator's charter. This is "authority to act".
2. The Hermes tool-call side emits an Ed25519-signed receipt referencing that
   same charter digest via its `delegation_chain_root` field. This is "what
   the agent actually did".
3. An independent walker (`_auditor_walk` in the test) verifies both
   signatures, confirms both carry the in-toto Decision Receipt v0.1
   predicate identifier, confirms the cross-side link resolves, and checks
   monotonic narrowing against the charter — all from the two artifacts plus
   two public keys plus the charter document.

## What's tested vs mocked

| Side | Source | Status in this test |
|---|---|---|
| APS delegation envelope | `hermes_aps.delegation_wrapper.wrap_skill_creation` | **Real.** Uses the library under test, signs with a fresh Ed25519 key, produces a DSSE-style in-toto envelope. |
| Tom's tool-call receipt | `hermes_decision_receipts.ReceiptSigner` | **Mocked locally.** The package isn't on PyPI yet (v0.1.0 target end of April 2026). The mock mirrors the canonical shape of `src/hermes_decision_receipts/signer.py` at clone time: envelope `{payload, signature: {alg, kid, sig}}`, JCS (RFC 8785) canonicalization with AIP-0001 adaptations, Ed25519 signing, the full field set including `delegation_chain_root`. |
| Cross-side walker | `_auditor_walk` in the test | **Real.** Pure stdlib + PyNaCl. Takes only the two artifacts, two public keys, and the charter. |

### Fields mirrored from Tom's repo

Copied verbatim from `ScopeBlind/hermes-decision-receipts` `src/hermes_decision_receipts/signer.py`:

- Envelope shape: `{payload: {...}, signature: {alg, kid, sig}}`
- Canonicalization: JCS (RFC 8785) — sorted keys, compact separators, UTF-8
- Signature: raw Ed25519 over canonical bytes (RFC 8032 internal hashing)
- `tool_input_hash`: `sha256:` + hex of JCS-canonicalized `tool_args`
- Chain linking: `previousReceiptHash` = `sha256:` + hex of prior canonical payload
- `kid` format: `sb:hermes:<first-12-chars-of-public-key-hex>`
- `sequence` is 1-indexed, monotonic per signer session
- `issued_at` is UTC ISO-8601 with millisecond precision and `Z` suffix
- Decision set: `{"allow", "deny", "require_approval", "compensated"}`

### Deliberate addition for cross-repo alignment

The mock payload carries a `predicateType` field set to
`https://veritasacta.com/attestation/decision-receipt/v0.1`.

Tom's v0.1.0-alpha.1 payload currently carries `spec:
draft-farley-acta-signed-receipts-01` without a `predicateType` field. This
repo's APS side does carry the `predicateType` URI. The field added here is
the bridge the bilateral-receipt predicate spec will formalize. When Tom's
v0.1.0 lands with aligned predicateType emission, the mock goes away and the
real signer drops in with no change to the walker.

## Cross-side linking mechanics

APS produces the charter root as a DigestSet:

```json
{"sha256": "<hex>"}
```

Tom's receipt expects it as a prefixed string:

```
"sha256:<hex>"
```

The test normalizes between the two forms in one place
(`_aps_charter_root_as_prefixed_string`). Once the two repos converge on the
in-toto `ResourceDescriptor.digest` shape, this adapter goes away and the
link becomes a direct equality check.

## Positive case

`test_roundtrip_positive`:

1. APS emits a signed skill-creation receipt authorizing
   `domain=code-review`, `persistent=true` under the `moderate.yaml` charter.
2. Mocked Tom signer emits a `read_file` tool-call receipt whose
   `delegation_chain_root` points at the charter digest.
3. APS-side chain verifier passes (signature, charter link, narrowing).
4. Receipt verifier passes (signature, predicateType, cross-link).
5. The auditor walker (no fixtures, only the five inputs) reproduces both
   validations from scratch.

## Negative cases

`test_roundtrip_tamper_aps_scope_breaks_link`:

- Mutate the charter's `skill_creation.domains` allowlist (add
  `data-export`).
- Recompute the charter root — it differs from the one the receipt was issued
  against.
- Cross-side verification raises `ChainError: delegation_chain_root
  mismatch`.
- Belt-and-braces: the original APS envelope verified against the mutated
  charter also raises `ChainError: delegationChainRoot mismatch`.

`test_roundtrip_tamper_receipt_payload_breaks_signature`:

- Flip the `decision` field from `allow` to `deny` after signing.
- JCS canonicalization produces different bytes; Ed25519 signature fails.

## Coverage boundaries

### What the test covers

- Signature validity on both sides (Ed25519, independently keyed).
- Shared predicate identifier
  (`https://veritasacta.com/attestation/decision-receipt/v0.1`).
- Cross-side cryptographic linkage via charter digest.
- Monotonic narrowing check on the APS side (domain must be in charter
  allowlist).
- Offline-ness: no network, no shared state between the two signing sides
  beyond the charter digest string.
- Tamper detection on both a content field (receipt payload) and a structural
  field (charter scope).

### What the test does not cover (yet)

- Multi-receipt chain linking on Tom's side (he tests it in
  `test_chain_linking`; we test one receipt here because cross-side linking
  is the focus).
- Bilateral receipt walker that emits a single combined attestation — that's
  the planned `hermes-audit-walker` repo, not in scope for this round-trip.
- Revocation: neither side has a revocation layer yet. A revoked charter or
  revoked signer key would still pass this test.
- Time-bound validity: `not_before` / `not_after` on the charter are not
  consulted by either signer or by the walker here. Production verifier must
  add clock-skew checks.
- VOPRF / KMS / HSM key material: both sides generate ephemeral keys per test
  run. Production deployments use hardware-rooted keys.
- Replay: the walker does not maintain seen-digest state. A receipt replayed
  out of sequence would not be caught by this walker alone (Tom's chain does
  catch it via `previousReceiptHash`, but the cross-side walker here
  validates only one receipt).
- The fixture drives a single skill-creation receipt on the APS side; the
  `charter.tool_call.allowed_tools` narrowing is only exercised indirectly
  through the charter document itself, not via an APS-side `wrap_tool_call`
  envelope that is then linked from Tom's receipt. A tighter composition
  would chain both APS skill-creation AND APS tool-call receipts under the
  same parent charter and then Tom's receipt on top; that's a follow-up when
  the bilateral-receipt predicate spec lands.

## Known limitations, to be tightened later

- Tom's repo has no PyPI release yet. The mock will be replaced with a real
  import once `hermes-decision-receipts==0.1.0` ships (target: end of April
  2026).
- The `predicateType` field is carried in the payload dict alongside Tom's
  current `spec: draft-farley-acta-signed-receipts-01`. Once both repos
  converge on the in-toto Statement wrapping
  ([in-toto/attestation#549](https://github.com/in-toto/attestation/pull/549)),
  the payload becomes a nested in-toto Statement with the existing Tom-side
  fields moved under `predicate`. The walker's assertions will shift from
  `payload["predicateType"]` to `json.loads(envelope["payload"])["predicateType"]`.
- `delegation_chain_root` formatting differs between the two sides
  (`"sha256:<hex>"` vs `{"sha256": "<hex>"}`). The bilateral-receipt
  predicate spec should pick one. The test normalizes in one place; when the
  spec lands, one side converts once and the adapter in
  `_aps_charter_root_as_prefixed_string` can be removed.

## References

- [NousResearch/hermes-agent#11692](https://github.com/NousResearch/hermes-agent/issues/11692)
  — tracking issue for the bilateral composition
- [ScopeBlind/hermes-decision-receipts](https://github.com/ScopeBlind/hermes-decision-receipts)
  — Tom Farley's signer (mocked in this test)
- [in-toto/attestation#549](https://github.com/in-toto/attestation/pull/549)
  — in-toto Decision Receipt predicate v0.1
- [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
  — IETF Internet-Draft for the receipt format
