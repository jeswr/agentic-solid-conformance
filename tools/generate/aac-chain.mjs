// AUTHORED-BY Claude Fable 5
//
// GENERATOR — vectors/agent-authz-credential (four-phase chain verification).
// Consolidates the golden-master decision matrix of
// accountable-agent-runtime@0aadd46 test/decision-matrix.test.ts (+ its committed
// snapshot) into language-neutral fixtures: REAL signed AgentAuthorizationCredentials
// (JSON-LD, eddsa-rdfc-2022), the bound ODRL policies (Turtle), a public keyring
// (controller documents), and per-case verdicts {authorized, phase, code}.
//
// EXTRACTION DISCIPLINE: the scenario, variants and verdicts are the runtime's own
// (runScenario + verifyAgentAuthority at the pinned sha). Each case's expected trio
// is (1) captured by executing the reference verifier and (2) HARD-ASSERTED against
// the runtime's committed golden snapshot values — a drift in either direction
// aborts generation. Keys are freshly generated per run (only PUBLIC halves are
// committed); verdicts are key-independent.

import { subtle } from "node:crypto";
import {
  CAST,
  runScenario,
  sameOriginController,
  VALID_UNTIL,
  verifyAgentAuthority,
} from "@jeswr/accountable-agent-runtime";
import { policyToTurtle } from "@jeswr/solid-odrl";
import { base58btcEncode } from "@jeswr/solid-vc";
import { stableJson, SuiteManifest, writeCase, writeFixture } from "../lib/emit.mjs";
import { join } from "node:path";
import { REPO_ROOT } from "../lib/emit.mjs";

const SPEC = "https://github.com/jeswr/agent-authz-credential-spec";
const SOURCE =
  "accountable-agent-runtime@0aadd46 test/decision-matrix.test.ts (+ __snapshots__/decision-matrix.test.ts.snap)";

/** Deep-clone a credential and flip one character of its proof value (a forged hop). */
function forge(vc) {
  const copy = structuredClone(vc);
  const proof = Array.isArray(copy.proof) ? copy.proof[0] : copy.proof;
  const v = proof.proofValue;
  proof.proofValue = v.slice(0, -1) + (v.endsWith("z") ? "A" : "z");
  return copy;
}

const base = await runScenario();

// --- keyring: public-only controller documents -------------------------------
const ACTORS = [
  { name: "alice", controller: CAST.alice, vm: CAST.aliceKeyVm },
  { name: "agent-a", controller: CAST.agentA, vm: CAST.agentAKeyVm },
  { name: "institute", controller: CAST.inst, vm: CAST.instKeyVm },
];
for (const a of ACTORS) {
  const key = base.keyRing.resolveKey(a.vm);
  if (key === undefined) throw new Error(`no key for ${a.vm}`);
  const jwk = await subtle.exportKey("jwk", key);
  delete jwk.key_ops;
  delete jwk.ext;
  // Multikey form: multicodec ed25519-pub (0xed 0x01) + the 32 raw public bytes.
  const raw = Buffer.from(jwk.x, "base64url");
  const publicKeyMultibase = base58btcEncode(new Uint8Array([0xed, 0x01, ...raw]));
  writeFixture(
    join(REPO_ROOT, "vectors", "agent-authz-credential", "keyring", `${a.name}.json`),
    stableJson({
      "@context": ["https://www.w3.org/ns/cid/v1"],
      id: a.controller,
      verificationMethod: [
        {
          id: a.vm,
          type: "Multikey",
          controller: a.controller,
          publicKeyMultibase,
          publicKeyJwk: jwk,
        },
      ],
      assertionMethod: [a.vm],
    }),
  );
}

// --- shared document bodies ---------------------------------------------------
const mandateTtl = await policyToTurtle(base.mandate);
const agreementTtl = await policyToTurtle(base.agreement);
const instituteTtl = await policyToTurtle(base.instituteInternal);
const credMandate = stableJson(base.credentials.mandate);
const credAgreement = stableJson(base.credentials.agreement);
const credInstitute = stableJson(base.credentials.instituteAgent);

// Variant documents (decision-matrix.test.ts, verbatim semantics).
const brokenAgreement = { ...base.agreement, delegatedUnder: "urn:not:present" };
const pastAgreement = {
  ...base.agreement,
  permissions: [
    {
      type: "permission",
      action: "read",
      target: CAST.records,
      assignee: CAST.inst,
      constraints: [
        { leftOperand: "purpose", operator: "eq", rightOperand: CAST.purpose },
        { leftOperand: "dateTime", operator: "lteq", rightOperand: "2026-01-01T00:00:00Z" },
      ],
    },
  ],
};
const launderAgreement = {
  ...base.agreement,
  permissions: [
    ...(base.agreement.permissions ?? []),
    { type: "permission", action: "distribute", target: CAST.records, assignee: CAST.inst },
  ],
};
const brokenAgreementTtl = await policyToTurtle(brokenAgreement);
const pastAgreementTtl = await policyToTurtle(pastAgreement);
const launderAgreementTtl = await policyToTurtle(launderAgreement);
const forgedAgreementCred = stableJson(forge(base.credentials.agreement));

const REVOCATION_DOC = `@prefix odrld: <https://w3id.org/jeswr/odrl-delegation#>.

<https://alice.solid.example/revocations/r1#it> a odrld:Revocation;
    odrld:revokedPolicy <${CAST.agreementId}>.
`;

const NOW = base.now.toISOString();
const READ_REQUEST = {
  action: "read",
  target: CAST.records,
  attributes: { purpose: CAST.purpose, dateTime: NOW },
};

/** The standard primary-chain / actor-chain document sets. */
const PRIMARY_DOCS = {
  "mandate.ttl": mandateTtl,
  "agreement.ttl": agreementTtl,
  "mandate.vc.json": credMandate,
  "agreement.vc.json": credAgreement,
};
const ACTOR_DOCS = {
  "institute-internal.ttl": instituteTtl,
  "institute-agent.vc.json": credInstitute,
};
const PRIMARY = {
  credentials: ["mandate.vc.json", "agreement.vc.json"],
  policies: ["mandate.ttl", "agreement.ttl"],
};
const ACTOR_CHAIN = {
  credentials: ["institute-agent.vc.json"],
  policies: ["institute-internal.ttl"],
};

// Base input every case starts from (the happy-path configuration).
const baseInput = () => ({
  primaryChain: PRIMARY,
  request: READ_REQUEST,
  rootPrincipal: CAST.alice,
  now: NOW,
  revoked: [],
  actor: CAST.agentR,
  actorChain: ACTOR_CHAIN,
});

// --- the case matrix (expected trios = the runtime's committed golden snapshot) --
const CASES = [
  {
    id: "happy",
    title: "HAPPY: the valid two-hop chain + identity-composition actor chain permits",
    clauses: ["#verification (all)", "#layering"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS },
    input: baseInput(),
    expected: { authorized: true, phase: "complete" },
  },
  {
    id: "actor-is-leaf-assignee",
    title: "HAPPY: the actor IS the leaf assignee — no second chain needed",
    clauses: ["#verification (Phase D, leaf-assignee rule)"],
    docs: PRIMARY_DOCS,
    input: { ...baseInput(), actor: CAST.inst, actorChain: undefined },
    expected: { authorized: true, phase: "complete" },
  },
  {
    id: "forged-hop",
    title: "FORGED HOP: a tampered proofValue → Phase A INVALID_SIGNATURE",
    clauses: ["#verification (Phase A: signature)", "#issuance"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS, "agreement-forged.vc.json": forgedAgreementCred },
    input: {
      ...baseInput(),
      primaryChain: { ...PRIMARY, credentials: ["mandate.vc.json", "agreement-forged.vc.json"] },
    },
    expected: { authorized: false, phase: "A", code: "INVALID_SIGNATURE" },
  },
  {
    id: "expired",
    title: "EXPIRED: now after validUntil → Phase A EXPIRED (stale-artifact replay control)",
    clauses: ["#verification (Phase A: validity window)", "#sec-replay (stale artifact)"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS },
    input: {
      ...baseInput(),
      now: "2027-08-01T00:00:00.000Z",
      request: {
        ...READ_REQUEST,
        attributes: { purpose: CAST.purpose, dateTime: "2027-08-01T00:00:00.000Z" },
      },
    },
    expected: { authorized: false, phase: "A", code: "EXPIRED" },
  },
  {
    id: "not-yet-valid",
    title: "NOT YET VALID: now before validFrom → Phase A NOT_YET_VALID",
    clauses: ["#verification (Phase A: validity window)"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS },
    input: {
      ...baseInput(),
      now: "2026-01-01T00:00:00.000Z",
      request: {
        ...READ_REQUEST,
        attributes: { purpose: CAST.purpose, dateTime: "2026-01-01T00:00:00.000Z" },
      },
    },
    expected: { authorized: false, phase: "A", code: "NOT_YET_VALID" },
  },
  {
    id: "chain-malformed",
    title: "CHAIN MALFORMED: a broken odrld:delegatedUnder edge → assembly CHAIN_MALFORMED",
    clauses: ["#verification (step 2: assemble the chain)"],
    docs: {
      "mandate.ttl": mandateTtl,
      "agreement-broken.ttl": brokenAgreementTtl,
      "mandate.vc.json": credMandate,
      "agreement.vc.json": credAgreement,
      ...ACTOR_DOCS,
    },
    input: {
      ...baseInput(),
      primaryChain: { ...PRIMARY, policies: ["mandate.ttl", "agreement-broken.ttl"] },
    },
    expected: { authorized: false, phase: "assembly", code: "CHAIN_MALFORMED" },
  },
  {
    id: "binding-mismatch",
    title: "BINDING MISMATCH: root credential issuer ≠ the trusted root principal → Phase B",
    clauses: ["#verification (Phase B: cross-binding)", "#sec-issuer-binding"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS },
    input: { ...baseInput(), rootPrincipal: "https://attacker.example/profile#me" },
    expected: { authorized: false, phase: "B", code: "BINDING_MISMATCH" },
  },
  {
    id: "revoked",
    title: "REVOKED: a revoked chain hop (odrld:Revocation direction) → Phase C REVOKED",
    clauses: ["#verification (Phase C)", "#revocation-verification (rule 2: statement → policy)"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS, "revocation.ttl": REVOCATION_DOC },
    input: { ...baseInput(), revoked: [CAST.agreementId] },
    expected: { authorized: false, phase: "C", code: "REVOKED" },
    note:
      "revocation.ttl is the published odrld:Revocation statement; `revoked` is the set a " +
      "caller derives from its odrld:revokedPolicy objects. The credential's OWN status list " +
      "is clean — a policy-layer revocation alone MUST deny (the union rule; the Bitstring " +
      "direction is pinned by the verify-credential-status cases).",
  },
  {
    id: "status-unreachable",
    title: "STATUS UNREACHABLE: the status source cannot be retrieved → fail-closed Phase C",
    clauses: ["#verification (Phase C)", "#sec-status-availability"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS },
    input: { ...baseInput(), statusUnreachable: true },
    expected: { authorized: false, phase: "C", code: "STATUS_RETRIEVAL_ERROR" },
  },
  {
    id: "out-of-scope",
    title: "OUT OF SCOPE: the actual use falls outside the granted purpose → Phase D",
    clauses: ["#verification (Phase D)", "#layering"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS },
    input: {
      ...baseInput(),
      request: {
        action: "read",
        target: CAST.records,
        attributes: { purpose: CAST.misusePurpose, dateTime: NOW },
      },
    },
    expected: { authorized: false, phase: "D", code: "POLICY_DENIED" },
  },
  {
    id: "expired-middle-hop",
    title: "EXPIRED MIDDLE HOP: a hop whose policy dateTime window passed → Phase D",
    clauses: ["#verification (Phase D)", "#sec-replay (policy-layer cut-off)"],
    docs: {
      "mandate.ttl": mandateTtl,
      "agreement-past.ttl": pastAgreementTtl,
      "mandate.vc.json": credMandate,
      "agreement.vc.json": credAgreement,
      ...ACTOR_DOCS,
    },
    input: {
      ...baseInput(),
      primaryChain: { ...PRIMARY, policies: ["mandate.ttl", "agreement-past.ttl"] },
    },
    expected: { authorized: false, phase: "D", code: "POLICY_DENIED" },
    note:
      "The CREDENTIAL is still within its validity window (Phase A passes); the POLICY's own " +
      "odrl:dateTime constraint has lapsed — the credential-validity ≠ authorization layering.",
  },
  {
    id: "prohibition-laundering",
    title: "PROHIBITION LAUNDERING: an ancestor prohibition blocks a leaf-permitted action → Phase D",
    clauses: ["#verification (Phase D)"],
    docs: {
      "mandate.ttl": mandateTtl,
      "agreement-launder.ttl": launderAgreementTtl,
      "mandate.vc.json": credMandate,
      "agreement.vc.json": credAgreement,
      ...ACTOR_DOCS,
    },
    input: {
      ...baseInput(),
      primaryChain: { ...PRIMARY, policies: ["mandate.ttl", "agreement-launder.ttl"] },
      request: { action: "distribute", target: CAST.records },
    },
    expected: { authorized: false, phase: "D", code: "POLICY_DENIED" },
  },
  {
    id: "over-length",
    title: "OVER LENGTH: chain longer than the verifier's maxChainLength → Phase D",
    clauses: ["#verification (Phase D)"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS },
    input: { ...baseInput(), maxChainLength: 1 },
    expected: { authorized: false, phase: "D", code: "POLICY_DENIED" },
  },
  {
    id: "identity-composition-missing",
    title: "IDENTITY COMPOSITION: actor ≠ leaf assignee and NO second chain → denied",
    clauses: ["#verification (Phase D: authenticated-agent rule)"],
    docs: PRIMARY_DOCS,
    input: { ...baseInput(), actorChain: undefined },
    expected: { authorized: false, phase: "composition", code: "IDENTITY_COMPOSITION_FAILED" },
  },
  {
    id: "identity-composition-wrong-root",
    title:
      "IDENTITY COMPOSITION: second chain not rooted at the leaf assignee (the primary chain replayed as the actor chain) → denied",
    clauses: ["#verification (Phase D: authenticated-agent rule)", "#sec-replay"],
    docs: PRIMARY_DOCS,
    input: { ...baseInput(), actorChain: PRIMARY },
    expected: { authorized: false, phase: "composition", code: "IDENTITY_COMPOSITION_FAILED" },
  },
  {
    id: "identity-composition-wrong-leaf",
    title:
      "IDENTITY COMPOSITION: a correctly-rooted second chain authorizing a DIFFERENT party is rejected for the actor",
    clauses: ["#verification (Phase D: authenticated-agent rule)"],
    docs: { ...PRIMARY_DOCS, ...ACTOR_DOCS },
    input: { ...baseInput(), actor: "https://institute.example/agents/rogue#it" },
    expected: { authorized: false, phase: "composition", code: "IDENTITY_COMPOSITION_FAILED" },
  },
];

// --- generate + verify against the reference verifier -------------------------
const manifest = new SuiteManifest({
  suite: "agent-authz-credential",
  spec: SPEC,
  description:
    "verify-agent-authority vectors for Agent Authorization Credentials: the four-phase decision matrix (assembly, Phase A signature/validity, Phase B cross-binding, Phase C status∪revocation fail-closed, Phase D delegated-policy evaluation) plus the identity-composition rule. Signed eddsa-rdfc-2022 credentials; public keys in keyring/.",
});

/** Materialize a chain input {credentials, policies} back to runtime objects. */
function chainFromDocs(docs, chainRef) {
  return {
    credentials: chainRef.credentials.map((f) => JSON.parse(docs[f])),
    policies: chainRef.policies.map((f) => policyByFile.get(f)),
  };
}
// Policy objects by filename (the generator knows the mapping; the CHECKER re-parses Turtle).
const policyByFile = new Map([
  ["mandate.ttl", base.mandate],
  ["agreement.ttl", base.agreement],
  ["institute-internal.ttl", base.instituteInternal],
  ["agreement-broken.ttl", brokenAgreement],
  ["agreement-past.ttl", pastAgreement],
  ["agreement-launder.ttl", launderAgreement],
]);

let failures = 0;
for (const c of CASES) {
  const input = c.input;
  const r = await verifyAgentAuthority(chainFromDocs(c.docs, input.primaryChain), {
    request: input.request,
    rootPrincipal: input.rootPrincipal,
    now: new Date(input.now),
    resolveKey: base.keyRing.resolveKey,
    isControlledBy: sameOriginController,
    revoked: input.revoked,
    ...(input.statusUnreachable !== undefined && { statusUnreachable: input.statusUnreachable }),
    ...(input.maxChainLength !== undefined && { maxChainLength: input.maxChainLength }),
    actor: input.actor,
    ...(input.actorChain !== undefined && {
      actorChain: chainFromDocs(c.docs, input.actorChain),
    }),
  });
  const actual = { authorized: r.authorized, phase: r.phase, ...(r.code && { code: r.code }) };
  const want = c.expected;
  if (
    actual.authorized !== want.authorized ||
    actual.phase !== want.phase ||
    actual.code !== want.code
  ) {
    failures++;
    console.error(`MISMATCH ${c.id}: want ${JSON.stringify(want)} got ${JSON.stringify(actual)}`);
    continue;
  }

  const caseJson = {
    id: `agent-authz-credential/${c.id}`,
    title: c.title,
    spec: SPEC,
    clauses: c.clauses,
    operation: "verify-agent-authority",
    input: {
      primaryChain: input.primaryChain,
      request: input.request,
      rootPrincipal: input.rootPrincipal,
      now: input.now,
      revoked: input.revoked,
      ...(input.statusUnreachable !== undefined && { statusUnreachable: input.statusUnreachable }),
      ...(input.maxChainLength !== undefined && { maxChainLength: input.maxChainLength }),
      ...(input.actor !== undefined && { actor: input.actor }),
      ...(input.actorChain !== undefined && { actorChain: input.actorChain }),
    },
    expected: c.expected,
    source: SOURCE,
    ...(c.note !== undefined && { note: c.note }),
  };
  const rel = writeCase("agent-authz-credential", c.id, caseJson, c.docs);
  manifest.add(caseJson, rel);
  console.log(`agent-authz-credential/${c.id}: ${JSON.stringify(actual)}`);
}

if (failures > 0) {
  console.error(`${failures} verdict mismatches vs the golden matrix — vectors NOT written`);
  process.exit(1);
}
manifest.write();
console.log(`agent-authz-credential (chain): ${CASES.length} cases written`);
console.log(`grant window: ${NOW} within [${base.credentials.mandate.validFrom}, ${VALID_UNTIL}]`);
