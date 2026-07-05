<!-- AUTHORED-BY Claude Fable 5 -->

# LWS alignment — the conformance fabric and the homing rule

**Substrate:** [JLWS — Linked Web Storage, clean-slate editor's draft](https://github.com/jeswr/lws-spec)
(core `index.html` + RDF Content Transformation Profile `rdf-transform.html`). The
composition design this document lands is the sibling half of
`lws-spec/docs/alignment/conformance-vectors.md` (JLWS DECISIONS.md D21).

## Verdict: this repo is the shared conformance FABRIC; JLWS adopts it by format

JLWS already composes with this repo in the deepest way available: its own
`test-vectors/` suite (125 cases) is **written in this repo's format** (per-case clause
pins, `anyOf`/`errorOneOf`, `preconditions`, a `GAPS.md`, committed TEST-ONLY keys), and
the JLWS spec's test-vectors appendix names this repo as the format source. The alignment
work here is therefore not a relationship section but a **division of labour** plus the
pure-function composition cases that fall on this repo's side of it.

## The homing rule (adopted; DECISIONS.md D11)

One rule decides where a composition vector lives, by **system under test**:

| System under test | Home | Provenance model |
|---|---|---|
| The JLWS **server/AS surface** (HTTP shapes, storage description, PRM, token validation, query gating) | `lws-spec/test-vectors/` | spec-derived verdicts (that repo's D20) |
| A **pure agent-layer function** (chain evaluation, credential verify, PD hashing/codec) | this repo's `vectors/` | reference-impl-extracted verdicts (this repo's D1) |

The two provenance models never mix inside one repo's suites — that keeps this repo's
extraction guarantee (a vector disagreement is always a three-way diff: spec ↔ reference
impl ↔ new impl) intact.

## What landed HERE: the a2a-rdf representation-stability pair

Two cases in `vectors/a2a-rdf/` (verdicts extracted from the pinned `@jeswr/solid-a2a`
codec, `e5ff315`, 0.2.0):

- **`pd-hash-stable-across-representations`** — `verify-pd-pin` of the grant-access PD as
  an rdf-1-faithful **expanded JSON-LD** rendering against the Turtle-derived pin →
  accept. Pins that the protocol hash is computed over the **parsed graph** (a2a-rdf spec
  §Content addressing steps 1–3), so under the JLWS RDF Content Transformation Profile's
  `rdf-1` contract (`rdf-transform.html` §Transformation semantics: derived
  representations are graph-isomorphic — no triples added, none removed) a PD stored as
  Turtle and served as JSON-LD pins identically. The generator **hard-asserts** the
  JSON-LD fixture canonicalizes to byte-identical RDFC-1.0 N-Quads before writing it, so
  the fixture cannot silently drift from the Turtle original. (The Turtle half of the
  pair is the existing `pd-pin-match`, same pinned hash.)
- **`pd-hash-rejects-graph-change`** — the same rendering plus exactly **one added
  triple** (`dcterms:description`; the delta is generator-asserted) → reject. Proves the
  acceptance above comes from graph identity, not lenient JSON-LD handling: a one-triple
  graph delta breaks the pin regardless of serialization.

Mechanics: the `verify-pd-pin` abstract operation gained an optional `mediaType` input
member (default `text/turtle`) — the operation itself (hash the parsed graph, compare) is
serialization-agnostic and unchanged.

## What deliberately did NOT land here (and where it is)

Recorded as pointers in [`GAPS.md`](../GAPS.md) ("LWS composition" section):

- **RDF-transform opt-in advertised** (storage-description `ContentNegotiation` +
  `conformsTo`, 406-on-unparseable, per-representation ETags) — JLWS server surface →
  `lws-spec/test-vectors/` (`rdf-transform` + `discovery` suites).
- **PoP over the LWS audience** (DPoP/DPoP-SK accept/reject against the realm-audienced
  token: PRM shape, establishment, attestation accept/bad-sig/replay/expired) — JLWS
  server surface → `lws-spec/test-vectors/`, as a **planned** `vectors/dpop-sk/` suite
  (8 cases specified in `lws-spec/docs/alignment/dpop-sk.md` §3, riding the
  implementation increment; until it lands the deferral is that repo's GAPS.md
  `core#rs-validation` row; only the `none` channel binding is deterministic,
  `tls-exporter` stays in that GAPS.md permanently).
- **a2a-rdf discovery over LWS** (the `AgentInteractionService` storage-description entry
  parse + unknown-type forward-compatibility) — JLWS server surface →
  `lws-spec/test-vectors/vectors/discovery/`; the `sd-agent-interaction-service` case is
  **specified, not yet landed** (it rides the config-gated storage-description entry,
  `lws-spec/docs/alignment/a2a-rdf.md` §3–§4).
- **a2a-rdf negotiation under LWS auth** — no new function to vector: the
  `A2A-Extensions`/handshake negotiation and the fail-closed no-silent-downgrade rule are
  auth-scheme-independent (the hash, not the storage's token-presentation mode, is the
  trust anchor), and their function is already fully pinned here (`decode-handshake`,
  `may-downgrade-to-nl`); the envelope half remains this repo's standing envelope gap.
