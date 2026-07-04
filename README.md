<!-- AUTHORED-BY Claude Fable 5 -->

# agentic-solid-conformance

**Shared conformance test vectors for the agentic-accountability specifications** — the
language-neutral golden inputs and expected outputs an **independent implementation** must
reproduce to claim conformance. This is the "make the second independent implementation
measurable" artifact of the Accountable Web of Agents programme (unite `decisions/0001`;
`accountable-agent-runtime` design).

Three vector suites, one per spec — **56 cases**:

| Suite | Cases | Spec under test | Reference implementation the verdicts were extracted from |
|---|---|---|---|
| [`vectors/odrl-delegation/`](./vectors/odrl-delegation/) | 13 | [ODRL Agent-Delegation Profile](https://github.com/jeswr/solid-odrl) (`https://w3id.org/jeswr/odrl-delegation`) | `@jeswr/solid-odrl` `evaluateDelegated` @ `18df183` (branch `feat/delegation-profile`) |
| [`vectors/agent-authz-credential/`](./vectors/agent-authz-credential/) | 29 | [Agent Authorization Credentials](https://github.com/jeswr/agent-authz-credential-spec) (unofficial CCG-shaped draft) | `@jeswr/accountable-agent-runtime` `verifyAgentAuthority` @ `0aadd46` (four-phase chain verifier) + `@jeswr/solid-vc` @ `d6b4e34` (branch `feat/mtr4-agent-authz-builder-followups`: status gate, policy binding, presentation verification) |
| [`vectors/a2a-rdf/`](./vectors/a2a-rdf/) | 14 | [RDF Protocol Documents — an A2A Extension](https://github.com/jeswr/a2a-rdf-extension) (`https://w3id.org/jeswr/a2a-rdf/v1`) | `@jeswr/solid-a2a` @ `15ed62a` (0.2.0: RDFC-1.0 protocol hashing, handshake codec) |

Case inventory at a glance:

- **odrl-delegation** (`evaluate-delegated-chain`): valid-1hop, valid-2hop,
  nextpolicy-mandated (the three permits); over-broad, expired-mid-chain, cycle,
  depth-exceeded (default budget + explicit `lteq 1`), nextpolicy-out-of-scope,
  nextpolicy-violated, revoked (with the `odrld:Revocation` document),
  use-does-not-grant-delegation (§3.2 privilege-escalation guard),
  prohibition-laundering (the denies).
- **agent-authz-credential**: the 16-case four-phase chain matrix
  (`verify-agent-authority`: happy, actor-is-leaf-assignee; chain-malformed; forged-hop,
  expired, not-yet-valid; binding-mismatch; revoked, status-unreachable; out-of-scope,
  expired-middle-hop, prohibition-laundering, over-length; the three
  identity-composition rejections) + 5 Bitstring status cases
  (`verify-credential-status`: clear-accept, revoked-bit, suspension-bit, unreachable,
  wrong-issuer) + 3 presentation-replay cases (`verify-presentation-replay`) + 5
  policy-content-binding cases (`resolve-bound-policy`: embedded, bare-IRI reject,
  digest match, digest mismatch, unreachable).
- **a2a-rdf**: the RDFC-1.0 protocol hash of the spec's grant-access Protocol Document
  (`rdfc10-hash`, reproducing the spec's published `sha256:4af1e70e…` with the canonical
  N-Quads shipped byte-exact), pin verification accept/tamper-reject (`verify-pd-pin`),
  5 strict handshake-decode cases (`decode-handshake`), the 4-row no-silent-downgrade
  decision table (`may-downgrade-to-nl`), and SHACL intent validation accept/reject
  (`validate-intent`).

The vectors are **self-describing data** — JSON case files referencing Turtle / JSON-LD input
documents — with **no dependency on any `@jeswr` code**. Any implementation, in any language,
can consume them: parse the inputs, run the named abstract operation, compare against
`expected`. The `tools/` directory holds the generator and a consistency-check runner pinned
to the reference implementations; those are *local tooling*, not part of the conformance
contract.

**Extraction, not re-derivation.** Every expected verdict was captured by *executing the
pinned reference implementation* over the serialized fixtures (and, where a golden-master
matrix already existed — `accountable-agent-runtime/test/decision-matrix.test.ts` +
snapshot, `solid-odrl/test/characterization.test.ts` "delegation decision matrix" — the case
set was consolidated from it). The consistency checker re-executes every case from the
on-disk fixtures, so a vector that drifted from the reference implementation fails the gate.

---

## Vector schema

Each suite directory contains:

```
vectors/<suite>/
  manifest.json          # suite id, spec IRI, schema version, list of case files
  cases/<case-id>/
    case.json            # the vector: operation, inputs (inline or by file ref), expected
    *.ttl / *.json / …   # input documents referenced by case.json (relative paths)
  keyring/               # (agent-authz-credential only) controller documents w/ public keys
```

`case.json`:

```jsonc
{
  "id": "odrl-delegation/valid-1hop",     // unique within the repo
  "title": "valid 1-hop chain → permit",
  "spec": "https://w3id.org/jeswr/odrl-delegation",
  "clauses": ["§5.1", "§5.2", "§6"],      // the normative clauses this vector pins
  "operation": "evaluate-delegated-chain", // an abstract operation defined below
  "input": { /* operation-specific; file refs are relative to the case dir */ },
  "expected": { /* operation-specific */ },
  "source": "solid-odrl@18df183 test/characterization.test.ts"  // where the verdict was extracted
}
```

A **conforming implementation** of a spec MUST, for every case in that spec's manifest,
produce a result equal to `expected` (field-by-field; fields the implementation does not
emit natively must be derivable — e.g. an implementation with different error-code strings
must publish a total mapping onto the vector codes and apply it consistently).

### File-reference convention

Any input field whose value is a string ending in `.ttl`, `.nq`, `.jsonld`, or `.json` **and**
naming an existing file in the case directory is a document reference; the document's bytes
are the input. Everything else is a literal value. (The manifests never mix the two forms in
one field.)

---

## Abstract operations

### 1. `evaluate-delegated-chain` — ODRL Agent-Delegation Profile §5–§7

```
evaluate-delegated-chain(chain, request, now, revoked, revocationDocuments?) → { decision }
```

- `chain`: ordered list (root first) of ODRL policy documents (Turtle, one policy per file;
  profile `https://w3id.org/jeswr/odrl-delegation`).
- `request`: `{ agent?, action, target, attributes? }` — the request context
  (`attributes.dateTime` / `attributes.purpose` feed `odrl:dateTime` / `purpose`
  constraints; the evaluator MUST inject the true remaining depth for
  `odrld:delegationDepth`, ignoring caller-asserted values — profile §4.1).
- `now`: the single evaluation instant (ISO 8601).
- `revoked` + `revocationDocuments`: the effective revoked set (profile §7) is the
  UNION of the literal `revoked` IRIs and, for every `odrld:Revocation` document listed
  in `revocationDocuments`, its `odrld:revokedPolicy` objects (profile §4.3). An
  implementation must actually PARSE the revocation statements — the cases that ship one
  keep the literal array empty.
- `expected.decision`: `"permit"` or `"deny"` — two-valued, fail-closed (profile §5:
  there is **no** `notApplicable` for a delegated chain).

### 2. `verify-agent-authority` — Agent Authorization Credentials §Verification

The full four-phase chain verification (AAC spec `#verification`; phases A–D plus the
assembly and identity-composition steps).

```
verify-agent-authority(primaryChain, options) → { authorized, phase, code? }
```

- `primaryChain`: `{ credentials: [vc.json …], policies: [policy.ttl …] }` — root first;
  credential *i* binds policy *i*.
- `options`:
  - `request`, `now`, `revoked`, `revocationDocuments` — as in operation 1;
  - `rootPrincipal`: the trusted root principal the root credential's issuer must equal
    (Phase B);
  - `statusUnreachable` (boolean, default false): models "the status source could not be
    retrieved" — a conforming verifier MUST fail closed (Phase C
    `STATUS_RETRIEVAL_ERROR`);
  - `maxChainLength` (optional): the verifier's absolute chain-length cap;
  - `actor` (optional): the authenticated WebID performing the request;
  - `actorChain` (optional): a second `{credentials, policies}` chain rooted at the primary
    chain's leaf assignee, authorizing `actor` (the identity-composition rule: *holding* a
    chain is not authority — *being* the delegate it names is; when `actor` ≠ the leaf
    assignee, a valid second chain from the leaf assignee to `actor` is REQUIRED).
- Key resolution: every credential's `proof.verificationMethod` resolves via the suite's
  [`keyring/`](./vectors/agent-authz-credential/keyring/) controller documents
  (public keys as both `publicKeyJwk` and Multikey `publicKeyMultibase`). The
  issuer↔key controller binding (AAC `#sec-issuer-binding`) holds in every fixture:
  each verification method is listed under `assertionMethod` in a controller document
  whose `id` is the credential's issuer (fixtures also keep the verification method on
  the issuer's origin, so an origin-based check agrees).
- `expected`:
  - `authorized`: boolean;
  - `phase`: `"complete"` (authorized) or the failing step — `"assembly"`, `"A"`, `"B"`,
    `"C"`, `"D"`, `"composition"`;
  - `code` (deny only): `CHAIN_MALFORMED`, `INVALID_SIGNATURE`, `EXPIRED`,
    `NOT_YET_VALID`, `BINDING_MISMATCH`, `REVOKED`, `STATUS_RETRIEVAL_ERROR`,
    `POLICY_DENIED`, `IDENTITY_COMPOSITION_FAILED`.
  An implementation with its own code vocabulary must map it totally onto these.

### 3. `verify-credential-status` — AAC §Revocation (Bitstring direction)

The credential-layer status gate in isolation (AAC `#revocation-verification` rule 1:
bit → policy), including the fail-closed availability rule (`#sec-status-availability`).

```
verify-credential-status(credential, documents, now) → { verified, codes }
```

- `credential`: a signed VC (JSON-LD) carrying a `credentialStatus`
  `BitstringStatusListEntry`.
- `documents`: a URL → file map standing in for the network: the
  `statusListCredential` URL maps to a signed `BitstringStatusListCredential` document
  (Turtle), or to `{ "status": 404 }` for the unavailability case. Implementations MUST
  NOT fetch anything outside this map.
- `expected.verified`: boolean; `expected.codes`: the deny codes (`REVOKED`,
  `SUSPENDED`, `STATUS_RETRIEVAL_ERROR`) — empty when verified.

### 4. `verify-presentation-replay` — AAC §Presentations / `#sec-replay`

The stolen-presentation replay control: a Verifiable Presentation is bound to a
`challenge`/`domain`; verification with the wrong expectation MUST fail.

```
verify-presentation-replay(presentation, challenge, domain, now) → { verified, codes }
```

- `presentation`: a signed VP (JSON-LD) whose authentication-purpose proof binds a
  challenge and domain; the holder's key resolves via the keyring.
- `challenge` / `domain`: what THIS verifier expects; a proof bound to anything else is a
  replay and MUST fail.
- `expected.verified`: boolean; `expected.codes`: the deny codes (`CHALLENGE_MISMATCH`,
  `DOMAIN_MISMATCH`) — empty when verified.

### 5. `resolve-bound-policy` — AAC §Policy-content binding / §Verification step 1

```
resolve-bound-policy(credential, documents) → { ok, form?, codes }
```

- `credential`: a signed VC whose `credentialSubject` carries `svc:policy` — embedded
  content, a reference with a signed digest (`relatedResource`-style `digestSRI` /
  `digestMultibase`), or a bare IRI.
- `documents`: the URL → file map for by-reference resolution (as in operation 3).
- `expected`: `ok` + the accepted binding `form` (`"embedded"` / `"reference"`), or
  `codes: ["POLICY_INTEGRITY"]` — a bare digest-less reference, a digest mismatch, and an
  unreachable policy document MUST all be rejected.

### 6. `rdfc10-hash` — A2A RDF extension §Content addressing

```
rdfc10-hash(graph) → { hash, canonical }
```

- `graph`: an RDF document (Turtle). Canonicalize with RDFC-1.0 to canonical N-Quads;
  SHA-256 the UTF-8 bytes; render `"sha256:" + lowercase-hex`.
- `expected.hash`: the pinned hash; `expected.canonical`: the canonical N-Quads file
  (byte-exact, LF line endings) — provided so a failing implementation can diff the
  canonicalization step from the digest step.

### 7. `verify-pd-pin` — A2A RDF extension §Content addressing (rejection rule)

```
verify-pd-pin(body, pinnedHash) → { ok }
```

`ok` is true iff `rdfc10-hash(body).hash == pinnedHash`. A mismatch means the fetched
Protocol Document MUST be rejected and the exchange treated as never upgraded.

### 8. `decode-handshake` — A2A RDF extension §Upgrade offer / §Upgrade response

```
decode-handshake(payload) → { ok } | { ok: false }
```

Strict structural validation of an `upgrade-offer` / `upgrade-response` JSON payload.
`expected.ok=false` cases pin the MUST-reject rules: a `required` or `accept` member that
is missing-where-required or not a JSON boolean MUST be rejected, never coerced (the
malformed-flag coercion would silently weaken the no-silent-downgrade rule).

### 9. `may-downgrade-to-nl` — A2A RDF extension §The no-silent-downgrade rule

```
may-downgrade-to-nl(offer, response) → { downgrade }
```

`downgrade` is true **only** when `response.protocolHash == offer.protocolHash` AND
`offer.required == false` AND `response.accept == false`. Every other combination —
including an accepted offer (proceed in RDF, NL simply unused) and a declined `required`
offer (abort with an error) — yields false.

### 10. `validate-intent` — A2A RDF extension §Message-content binding (pre-action validation)

```
validate-intent(dataGraph, shapesGraph) → { conforms }
```

Standard SHACL validation of an intent graph against the hash-pinned Protocol Document's
request shape (the shapes graph ships as the PD document itself; its non-shape triples are
inert to a SHACL engine). Any conformant SHACL processor is a valid implementation.

---

## Running the suite against your implementation

1. For each `vectors/<suite>/manifest.json`, load every listed `case.json`.
2. Dispatch on `operation` to your implementation of the abstract operation.
3. Resolve file-reference inputs relative to the case directory.
4. Compare your result to `expected` (deep equality after your documented code-mapping).
5. Conformance to a spec = **all** of that suite's cases pass. Report failures by case
   `id` + `clauses` (the clause list tells you which normative statement you broke).

The repository's own gate does exactly this with the pinned reference implementations:

```bash
cd tools && npm install && npm test   # regenerates nothing; re-checks every case from disk
```

`tools/` is local tooling (it depends on `@jeswr/accountable-agent-runtime`, `@jeswr/solid-a2a`,
`@jeswr/solid-odrl`, and `@jeswr/solid-vc`, all pinned to published git SHAs now that every
sibling repo is publicly published); the vectors themselves never require it.

## Regenerating vectors

```bash
cd tools && npm install && npm run generate
```

Regeneration re-signs the credential fixtures with **fresh keys** (keys are generated per
run and only public halves are committed), so credential bytes and the keyring change; the
verdicts must not. The checker gates that invariant. Never hand-edit generated fixtures.

## Traceability

Each case's `clauses` field pins the normative statements it tests; the per-suite
`manifest.json` carries a `clauseIndex` (clause → case ids) so you can see at a glance
which MUSTs are vector-covered — and the honest inverse is below.

## Normative statements with NO deterministic vector (honest gaps)

See [`GAPS.md`](./GAPS.md): the normative requirements of the three specs for which this
suite deliberately ships no vector, each with the reason (network/trust behaviour,
statefulness, non-determinism, or out-of-scope-for-data-vectors) — so "passes the vector
suite" is never mistaken for "conforms to every MUST".

## Provenance

Vectors extracted and consolidated by Claude Fable 5 (AI-assisted; maintainer-reviewed
repo policy) from the pinned reference implementations named above, 2026-07-03. Design
decisions: [`DECISIONS.md`](./DECISIONS.md). License: MIT.
