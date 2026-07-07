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

## D11 — LWS-composition vectors: only the pure-function half homes here

Alignment with the JLWS clean-slate Linked Web Storage draft (`jeswr/lws-spec` DECISIONS.md
D21; its `docs/alignment/conformance-vectors.md` fixes the homing rule this decision
adopts). The rule: a vector homes by its **system under test** — pure agent-layer
functions HERE (verdicts extracted from pinned reference implementations, D1), the JLWS
server/AS surface in `lws-spec/test-vectors/` (spec-derived verdicts, that repo's D20).
The two provenance models never mix inside one repo's suite. So this repo gains exactly
the two pure-function composition cases (`a2a-rdf/pd-hash-stable-across-representations`,
`a2a-rdf/pd-hash-rejects-graph-change` — the protocol hash pins the parsed graph, making
the pin representation-stable under the rdf-1 transform contract and broken by a
one-triple delta in any serialization), while the PoP-over-LWS-audience matrix, the
RDF-transform advertisement surface, and the `AgentInteractionService` discovery parse
home in lws-spec (GAPS.md's "LWS composition" table records each pointer). Mechanics: the
`verify-pd-pin` operation gains an optional `mediaType` input member (default
`text/turtle`) rather than a new operation — the abstract operation is unchanged (hash
the parsed graph), only the fixture's serialization varies; the JSON-LD fixture is
authored in expanded, context-free form (the rdf-1 contract's own no-remote-context
discipline) and the generator HARD-ASSERTS it canonicalizes to byte-identical RDFC-1.0
N-Quads before writing (an unfaithful rendering fails generation, so the fixture cannot
drift from the Turtle original). The suite regen also re-extracted all a2a-rdf verdicts
against the currently pinned codec sha (`e5ff315`, still 0.2.0), updating the stale
`15ed62a` source strings. **Rejected:** homing spec-derived JLWS server-surface cases
here (would mix provenance models and break D1's extraction guarantee); a separate
`verify-pd-pin-jsonld` operation (the operation is serialization-agnostic by definition —
a parameter, not a new contract).

## D12 — Companion statement ids are the migrated form of `clauses`; derived, not hand-mapped

The vectors originally pinned normative statements by section string (`case.json.clauses`
+ manifest `clauseIndex` — e.g. `"§5.1"`, `"#verification (Phase D)"`). Those strings are
brittle: a spec re-headline silently breaks the pin. The
[spec-companion](https://github.com/jeswr/spec-companion) project (DESIGN §7) gives each
spec's normative statements **stable ids** (`AAC-VER-1`, `A2ARDF-DG-1`, …) in a sidecar
`spec.statements.ttl`, and asks this suite to migrate the clause pins to those ids as an
**additive** field, keeping both during the transition.

**Decision.** For every suite whose spec has a landed companion (`a2a-rdf`,
`agent-authz-credential`; `odrl-delegation` has none yet, so it is untouched), each case
gains a `statements` array and each manifest a `statementIndex` (+ a `statementCompanion`
provenance block pinning the companion IRI and its `sc:specVersion`). Crucially, the ids
are **not hand-mapped from the clause strings** — they are the inverse of the companion's
own `spec:testCase` links (the companion author already decided, per statement, which
vector cases exercise it). `tools/generate/statement-ids.mjs` reads the companion with the
sanctioned parser (`@jeswr/fetch-rdf`, no bespoke RDF parser) and writes the fields;
`tools/check/statement-ids.mjs` (in the base gate) re-derives the index from the committed
cases and fails on any asymmetry, so the two artifacts are provably one bidirectional
relation. This mirrors D1's ethos — the mapping is *extracted* from an authoritative
source, never a fresh hand-authored opinion — and keeps the vectors self-describing (the
check needs no companion at consume time; only regeneration reads the sibling repos).

**Rejected:** hand-mapping each `clauses` string to a statement id (re-encodes the
author's reading, the exact failure D1 avoids); replacing `clauses` outright (breaks
readers mid-transition; DESIGN §7 says keep both); vendoring a copy of each companion into
this repo (reintroduces the cross-repo drift spec-companion DESIGN §6 eliminates — the
companion in the spec's own repo stays the single source of truth).

**Discovered gap (follow-up, not a defect here).** The bidirectional check surfaced that
the `agent-authz-credential-spec` companion pins `identity-composition-missing` and
`identity-composition-wrong-leaf` to `AAC-VER-5` (the leaf-assignee rule) but does **not**
pin the sibling `identity-composition-wrong-root`, whose clause is the identical
`#verification (Phase D: authenticated-agent rule)`. That case is therefore left with no
`statements` field (honest — this suite never invents a companion link). The fix belongs
in the companion: add `vec:identity-composition-wrong-root` to `AAC-VER-5`'s `spec:testCase`
in `jeswr/agent-authz-credential-spec`; a later regen here then picks it up automatically.
