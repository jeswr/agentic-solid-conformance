<!-- AUTHORED-BY Claude Fable 5 -->

# Design decisions

Per-decision rationale for the vector-suite design, recorded so the maintainer (and the
second-implementation team) can audit the choices. Alternatives noted where a real choice
existed.

## D1 — Extraction from the pinned reference implementations, never re-derivation

Every expected verdict is captured by **executing** the pinned reference implementation
over the exact serialized fixtures shipped in the vector (and, for the chain matrix,
hard-asserted against the runtime's committed golden snapshot as a second witness). The
alternative — hand-writing expected outputs from the spec text — risks encoding the
author's *reading* of the spec rather than the behaviour the second implementation must
actually reproduce, and silently diverging from the reference. Consequence: a vector
disagreement is always a three-way diff (spec text ↔ reference impl ↔ new impl), never a
fourth hand-authored opinion.

## D2 — Vectors are self-describing data; tools/ is explicitly non-normative

The conformance contract is the `vectors/` tree alone: JSON case files + Turtle/JSON-LD
documents + the README's abstract-operation definitions. `tools/` (generator + checker)
depends on `@jeswr/accountable-agent-runtime`, `@jeswr/solid-a2a`, `@jeswr/solid-odrl`, and
`@jeswr/solid-vc` — all now published `@jeswr` sibling repos, pinned by `tools/package.json`
to a specific git SHA each — so tools/ cannot be part of the contract even in principle: it
is pinned reference-implementation *tooling*, not a normative dependency the vectors carry.
This is the "no @jeswr-code dependency" requirement made structural.

## D3 — Turtle as the normative policy form, verified by re-parse round-trip

ODRL policies ship as Turtle (the profile's normative RDF), not as the reference
implementation's internal JSON model. The generator *serializes → re-parses → evaluates*
and refuses to write a vector whose serialized-form verdict differs from the in-memory
verdict, so the shipped bytes provably carry everything the decision needs. Credentials
ship as JSON-LD (the VC 2.0 wire form; the proof is over the canonical RDF, so the JSON
document *is* the signed artifact).

## D4 — Public-only keyring as controller documents, fresh keys per generation

Only public halves are committed (a conformance repo must never ship private signing keys:
someone WILL copy fixtures into production trust stores). Keys are regenerated on every
`npm run generate`, so credential bytes churn but verdicts cannot — the checker gates that
invariant. Each key is published as a controller document carrying **both** Multikey
(`publicKeyMultibase`, the eddsa-rdfc-2022 native form) and JWK, so implementations on
either key-model consume the same fixture. The fixtures satisfy the issuer↔key controller
binding two ways at once (assertionMethod listing AND same-origin), so implementations
using either check agree.

## D5 — Case-level self-containment over shared fixture directories

Every case directory contains every document it references (the suite-level `keyring/` is
the one documented exception). Files are duplicated across cases (~1–3 KB each) in exchange
for: a case is inspectable/portable in isolation, and no case can be broken by editing
another's shared fixture. The `cycle-deny` case shows the flip side done right: the
repeated chain policy references the *same file twice*, because "the same document appears
twice" IS the semantics under test.

## D6 — Expected results pin decision-surface fields only

`evaluate-delegated-chain` pins `decision`; `verify-agent-authority` pins
`{authorized, phase, code}`; the credential-layer ops pin `{verified/ok, codes}`. Traces,
reasons, duty lists and error messages are deliberately unpinned — they are explainability
surface, legitimately implementation-specific. Error codes ARE pinned (they are the specs'
own normative vocabulary), with the documented total-mapping escape hatch for
implementations with native code vocabularies.

## D7 — The network is modelled as a case-declared `documents` map

Operations that would touch the network (`verify-credential-status`,
`resolve-bound-policy`) instead receive an explicit URL→document map; the case text forbids
fetching outside it. This keeps vectors deterministic and offline, and doubles as the
fail-closed availability probe (`{"status": 404}` entries). The cost — accepted — is that
genuinely network-behavioural MUSTs (SSRF discipline, freshness, no-dereference rules)
cannot be vectored; they are catalogued in GAPS.md instead of being faked.

## D8 — `statusUnreachable` stays an abstract boolean at the chain layer

The four-phase `verify-agent-authority` operation models status-source unavailability as a
flag rather than a full Bitstring fetch, mirroring the reference verifier's seam (its
Phase C consumes a revoked set + an unreachability signal; the Bitstring gate lives at the
credential layer). The Bitstring mechanics get their own credential-layer operation
(`verify-credential-status`) with real signed status-list fixtures — so both layers are
pinned without inventing a chain-layer API the reference does not have.

## D9 — The A2A hash vector ships the canonical N-Quads, not just the digest

`rdfc10-hash` expects both the `sha256:` value and the byte-exact RDFC-1.0 canonical
N-Quads file. A bare digest gives a failing implementer one bit of information; the
canonical bytes bisect the failure into canonicalization vs digest/rendering. The PD
fixture is the extension spec's own published example, and generation hard-asserts the
computed hash equals the spec's published `sha256:4af1e70e…` — cross-validating spec,
codec, and vector in one step.

## D10 — Incremental one-suite-per-commit history

Each spec's vectors landed as an independent commit (scaffold+delegation → AAC chain →
AAC status/presentation → A2A → binding additions), so an interruption at any point leaves
a coherent, gated repo. This mirrors the brief's interruption-resilience requirement.
