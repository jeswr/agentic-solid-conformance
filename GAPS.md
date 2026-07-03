<!-- AUTHORED-BY Claude Fable 5 -->

# Normative statements with NO deterministic vector

The honest inverse of the manifests' `clauseIndex`: the normative requirements of the three
specs this suite deliberately does **not** pin with a vector, each with the reason. Passing
the vector suite is therefore **necessary but not sufficient** for full conformance — an
implementation must still satisfy these by review/testing of its own.

Legend for *why not*:

- **network/trust** — the requirement governs how an implementation interacts with the live
  network or decides whom to trust; a data vector cannot observe it.
- **stateful** — the requirement spans multiple observations over time; a single
  input→output vector cannot express it.
- **behavioural emission** — the requirement says what an implementation must *do or
  publish* (write a trace, set a bit), not what a decision function must *return*.
- **envelope** — the requirement lives in the carrying protocol (A2A message structure,
  HTTP), outside the document payloads this suite ships.
- **vectorable, deferred** — deterministic and pinnable, just not yet extracted; tracked as
  a follow-up.

## ODRL Agent-Delegation Profile (`https://w3id.org/jeswr/odrl-delegation`)

| Clause | Requirement | Why no vector |
|---|---|---|
| §5 (preamble) | The caller MUST establish that `chain[0]` is the trusted root and that each hop is genuinely attributable to its `odrl:assigner` before evaluation | network/trust — the profile explicitly delegates this to the caller; the *credentialized* discharge of the same precondition IS pinned (AAC Phase B `binding-mismatch`, `forged-hop`) |
| §4.1 | A conforming evaluator MUST ignore **caller-asserted** `delegationDepth` request values | vectorable, deferred — needs the operation signature to carry a hostile `attributes.delegationDepth`; the *reserved-operand injection* itself is exercised implicitly by every depth case |
| §6.3 | Duties of every matched ancestor grant + each `grantUse` edge + the leaf **accumulate**, and under `requireDuties` the aggregate must be discharged | partially vectorable, deferred — the vectors pin `decision` only; pinning the aggregated duty *set* needs a stable cross-implementation duty serialization. Whether a duty was *discharged* is behavioural |
| §7 | A revocation statement SHOULD only be trusted when attributed to the revoked policy's own assigner or an ancestor assigner | network/trust (and a SHOULD) — the evaluator receives an already-trust-filtered revoked set; the vectors ship the `odrld:Revocation` document but cannot observe the trust filter |
| §7 | Revocation **freshness** (how recently the relying party fetched) is the caller's trust decision | network/trust |
| §8 | Acting systems SHOULD record actions as `prov:Activity` with `prov:qualifiedAssociation`/`prov:hadPlan`, enabling the audit walk | behavioural emission — the `delegationProvenance` PROV overlay itself is deterministic and **vectorable, deferred** (a canonical-graph vector) |
| §11 | A conforming **policy** asserts the profile IRI | vectorable, deferred — all shipped chains do assert it, but no negative case pins an evaluator's handling of a profile-less policy (the profile does not currently mandate rejection) |

## Agent Authorization Credentials (unofficial CCG-shaped draft)

| Clause | Requirement | Why no vector |
|---|---|---|
| `#verification` step 2 | *One credential per policy* — the presented set must bind each chain policy exactly once (branches/duplicates/gaps → `CHAIN_MALFORMED`) | partially covered (`chain-malformed` pins a broken `delegatedUnder` edge); the duplicate-credential and branch variants are **vectorable, deferred** |
| `#verification` Phase A | "a registered, **permitted** cryptosuite" — rejection of an unregistered suite | vectorable, deferred — needs a fixture signed with a suite outside the accepted registry |
| `#verification` Phase D | The requesting agent "MUST be the **authenticated** WebID (e.g. the DPoP-bound token's `webid` claim)" | envelope — the `actor` input models the *result* of authentication; the token-to-actor binding is the resource server's auth layer (covered by its own DPoP test surface) |
| `#revocation-publication` | An issuer revoking a hop MUST set the status bit AND SHOULD publish the `odrld:Revocation` statement; ancestors publish statements for descendants | behavioural emission (issuer-side); the *verification-side* consequences of both mechanisms are pinned |
| `#revocation-publication` rule 3 | Revocation is **permanent**: an issuer MUST NOT clear a set revocation bit; verifier-side monotonicity ("once observed revoked, a later clear read does not un-revoke") | stateful — spans two reads of the same status list; the reference implements it via an injectable `RevocationStore` |
| `#sec-status-availability` | Status **freshness policy** (how stale a cached status result may be) | network/trust |
| `#verification` (closing) | "MUST use **one evaluation instant** across all phases" | not independently observable — every vector supplies a single `now`, so a two-clock implementation *may* still pass; a differential vector would need a case engineered so phase clocks diverge across a boundary. Deferred as impractical without over-constraining implementations |
| Bitstring §"Bitstring" | The 131,072-entry minimum list size (herd privacy) — rejection of a too-short list | vectorable, deferred — the reference enforces it (`STATUS_RETRIEVAL_ERROR`); a short-list fixture was omitted to keep the status group focused |
| `#presentations` | Holder binding: the presenter must prove control of the credential's agent WebID (`HOLDER_UNVERIFIED`) | vectorable, deferred — the challenge/domain replay pair is pinned; the no-holder / wrong-holder rejections are extractable from the same solid-vc test file |
| `#issuance` | Issuer-controlled keys, one hop per credential, `assertionMethod` proof purpose | partially covered — `forged-hop` pins signature integrity and the keyring pins issuer↔key binding; a wrong-`proofPurpose` fixture is **vectorable, deferred** |

## A2A RDF extension (`https://w3id.org/jeswr/a2a-rdf/v1`)

| Clause | Requirement | Why no vector |
|---|---|---|
| §Agent Card declaration / §Activation | `AgentExtension` entry shape, `A2A-Extensions` negotiation, `Message.extensions` tagging | envelope — A2A envelope structures, outside the payload documents |
| §Upgrade response (RDF form) | A handshake **graph** MUST contain exactly one typed handshake subject; ambiguous graphs are rejected | vectorable, deferred — `handshakeFromRdf` in the reference codec enforces it; RDF-form handshake vectors (well-formed offer/response graphs + an ambiguous-graph reject) are a natural next group |
| §Content addressing | "Implementations MUST reject hash strings whose **prefix** they do not recognise" | vectorable, deferred — needs a `verify-pd-pin` case with e.g. `sha512:…` |
| §Handshake-skip | A client MAY skip the handshake for a card-declared PD but MUST still validate the intent | behavioural (the MUST-validate half is pinned by `validate-intent`) |
| §Message-content binding | Part `metadata` keys, media-type selection, "validate against the hash-verified copy only — never shapes fetched at message time" | envelope + network/trust |
| §Security considerations | SSRF-safe PD fetching, validation-cost bounds, untrusted-RDF hardening | network/resource behaviour — belongs to each implementation's security test surface (cf. `@jeswr/guarded-fetch`) |
| §PD model | "a validator MUST NOT dereference IRIs mentioned in the shapes (no `owl:imports`-style loading)" | network — a data vector cannot observe the *absence* of a fetch; testable only with an instrumented network layer |

## Deferred-but-vectorable follow-ups (extraction order)

1. AAC presentation holder-binding rejections (`HOLDER_UNVERIFIED`) — same source file as the replay pair.
2. AAC duplicate-credential / branch `CHAIN_MALFORMED` variants.
3. A2A RDF-form handshake graphs (incl. the ambiguous-graph reject) + unrecognised-hash-prefix rejection.
4. Bitstring too-short-list rejection (herd-privacy minimum).
5. ODRL `delegationProvenance` PROV-overlay canonical-graph vector; caller-asserted `delegationDepth` stripping; aggregated-duty pinning.
6. AAC unregistered-cryptosuite + wrong-proof-purpose rejections.
