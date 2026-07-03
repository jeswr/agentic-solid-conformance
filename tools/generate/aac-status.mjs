// AUTHORED-BY Claude Fable 5
//
// GENERATOR — vectors/agent-authz-credential, credential-layer sub-suites:
//
//   verify-credential-status    — the Bitstring Status List direction of the AAC
//                                 revocation mapping (#revocation-verification
//                                 rule 1, #sec-status-availability fail-closed),
//                                 extracted from solid-vc@d6b4e34
//                                 test/status-list.test.ts's acceptance/rejection
//                                 matrix (branch feat/mtr4-agent-authz-builder-followups).
//   verify-presentation-replay  — the stolen-presentation replay control
//                                 (#presentations / #sec-replay channel 3):
//                                 challenge/domain binding, from test/presentation.test.ts.
//
// Verdicts are captured by EXECUTING solid-vc@d6b4e34 over the serialized fixtures
// and hard-asserted against the expected outcome of the branch's test matrix.
// Appends to the agent-authz-credential manifest written by aac-chain.mjs.

import { gzipSync } from "node:zlib";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  generateKeyPairForSuite,
  issue,
  issueAgentAuthorization,
  signedCredentialToTurtle,
  signPresentation,
  verifyCredential,
  verifyPresentation,
} from "@jeswr/solid-vc";
import { base58btcEncode } from "@jeswr/solid-vc";
import { subtle } from "node:crypto";
import { REPO_ROOT, stableJson, writeCase, writeFixture } from "../lib/emit.mjs";

const SPEC = "https://github.com/jeswr/agent-authz-credential-spec";
const SOURCE_STATUS =
  "solid-vc@d6b4e34 (feat/mtr4-agent-authz-builder-followups) test/status-list.test.ts";
const SOURCE_VP =
  "solid-vc@d6b4e34 (feat/mtr4-agent-authz-builder-followups) test/presentation.test.ts";

// --- cast (distinct from the chain sub-suite so keyrings never collide) ------
const ISSUER = "https://status-issuer.example/org#id";
const ISSUER_VM = "https://status-issuer.example/keys#k1";
const PRESENTER = "https://presenter.example/agents/p#it";
const PRESENTER_VM = "https://presenter.example/keys#k1";
const LIST_URL = "https://status-issuer.example/status/list-1";
const TARGET = "https://alice.solid.example/data/records.ttl";
const TOTAL_ENTRIES = 131072; // the Bitstring Status List minimum
const INDEX = 42;
const NOW = "2026-08-01T00:00:00.000Z";
const CHALLENGE = "c-8f21-issued-by-verifier";
const DOMAIN = "https://verifier.example/authorize";

const issuerKey = await generateKeyPairForSuite(ISSUER_VM, "Ed25519");
const presenterKey = await generateKeyPairForSuite(PRESENTER_VM, "Ed25519");

// keyring controller documents (public halves only) — written AFTER verification
const keyringDocs = [];
for (const [name, controller, vm, key] of [
  ["status-issuer", ISSUER, ISSUER_VM, issuerKey],
  ["presenter", PRESENTER, PRESENTER_VM, presenterKey],
]) {
  const jwk = await subtle.exportKey("jwk", key.publicKey);
  delete jwk.key_ops;
  delete jwk.ext;
  const raw = Buffer.from(jwk.x, "base64url");
  keyringDocs.push({
    name,
    body: stableJson({
      "@context": ["https://www.w3.org/ns/cid/v1"],
      id: controller,
      verificationMethod: [
        {
          id: vm,
          type: "Multikey",
          controller,
          publicKeyMultibase: base58btcEncode(new Uint8Array([0xed, 0x01, ...raw])),
          publicKeyJwk: jwk,
        },
      ],
      assertionMethod: [vm],
    }),
  });
}

const resolveKey = (vm) =>
  vm === ISSUER_VM ? issuerKey.publicKey : vm === PRESENTER_VM ? presenterKey.publicKey : undefined;
const isControlledBy = (vm, issuer) =>
  (vm === ISSUER_VM && issuer === ISSUER) || (vm === PRESENTER_VM && issuer === PRESENTER);

/** Encode a bitstring (MSB-first) with `setBits` set → multibase-base64url GZIP. */
function encodeList(setBits) {
  const bytes = new Uint8Array(TOTAL_ENTRIES / 8);
  for (const i of setBits) {
    bytes[i >>> 3] |= 1 << (7 - (i & 7));
  }
  // multibase base64url ('u' prefix, no padding — Node's base64url is unpadded)
  return `u${Buffer.from(gzipSync(bytes)).toString("base64url")}`;
}

const STATUS_PURPOSE = "https://www.w3.org/ns/credentials/status#statusPurpose";
const STATUS_ENCODED_LIST = "https://www.w3.org/ns/credentials/status#encodedList";
const SVC_AUTHORIZES = "https://w3id.org/jeswr/solid-vc#authorizes";

/** Build + sign a BitstringStatusListCredential, serialized to Turtle. */
async function signedStatusList({ purpose = "revocation", setBits = [], key = issuerKey, issuer = ISSUER }) {
  const signed = await issue({
    credential: {
      issuer,
      id: LIST_URL,
      type: ["BitstringStatusListCredential"],
      credentialSubject: {
        id: `${LIST_URL}#list`,
        [STATUS_PURPOSE]: purpose,
        [STATUS_ENCODED_LIST]: encodeList(setBits),
      },
    },
    key,
  });
  return signedCredentialToTurtle(signed);
}

/** Build + sign an agent-authz hop credential carrying a credentialStatus entry. */
async function signedHop(statusPurpose) {
  return issue({
    credential: {
      issuer: ISSUER,
      type: ["AgentAuthorizationCredential"],
      credentialSubject: { id: ISSUER, [SVC_AUTHORIZES]: PRESENTER },
      credentialStatus: {
        type: "BitstringStatusListEntry",
        statusPurpose,
        statusListIndex: String(INDEX),
        statusListCredential: LIST_URL,
      },
    },
    key: issuerKey,
  });
}

/** The checker-identical fixture fetch over a documents map. */
function fixtureFetch(documents, bodies) {
  return async (url) => {
    const entry = documents[url];
    if (entry === undefined) return { ok: false, status: 404, headers: { get: () => null }, text: async () => "", arrayBuffer: async () => new ArrayBuffer(0) };
    if (typeof entry === "object") {
      return { ok: false, status: entry.status, headers: { get: () => null }, text: async () => "", arrayBuffer: async () => new ArrayBuffer(0) };
    }
    const body = bodies[entry];
    return {
      ok: true,
      status: 200,
      headers: { get: (n) => (n.toLowerCase() === "content-type" ? "text/turtle" : null) },
      text: async () => body,
      arrayBuffer: async () => new TextEncoder().encode(body).buffer,
    };
  };
}

// --- status cases -------------------------------------------------------------
const hopRevocation = await signedHop("revocation");
const hopSuspension = await signedHop("suspension");

const STATUS_CASES = [
  {
    id: "status-bit-clear-accept",
    title: "Bitstring status: revocation bit CLEAR → verified",
    clauses: ["#revocation-verification (rule 1)", "#credential-shape (credentialStatus)"],
    hop: hopRevocation,
    list: await signedStatusList({ setBits: [] }),
    documents: { [LIST_URL]: "status-list.ttl" },
    expected: { verified: true, codes: [] },
  },
  {
    id: "status-bit-set-revoked",
    title: "Bitstring status: revocation bit SET → deny REVOKED (bit → policy direction)",
    clauses: ["#revocation-verification (rule 1)", "#revocation-publication (rule 3)"],
    hop: hopRevocation,
    list: await signedStatusList({ setBits: [INDEX] }),
    documents: { [LIST_URL]: "status-list.ttl" },
    expected: { verified: false, codes: ["REVOKED"] },
    note:
      "The odrld:Revocation direction (statement → policy) is pinned by the chain-level " +
      "`revoked` case; disagreement between the two sources resolves CLOSED (the union): " +
      "either source alone denies.",
  },
  {
    id: "status-suspension-bit-set",
    title: "Bitstring status: suspension bit SET → deny SUSPENDED (distinct, reversible purpose)",
    clauses: ["#revocation-publication (rule 3: suspension ≠ revocation)"],
    hop: hopSuspension,
    list: await signedStatusList({ purpose: "suspension", setBits: [INDEX] }),
    documents: { [LIST_URL]: "status-list.ttl" },
    expected: { verified: false, codes: ["SUSPENDED"] },
  },
  {
    id: "status-list-unreachable",
    title: "Bitstring status: the status list cannot be retrieved (404) → fail-closed deny",
    clauses: ["#sec-status-availability", "#verification (Phase C)"],
    hop: hopRevocation,
    documents: { [LIST_URL]: { status: 404 } },
    expected: { verified: false, codes: ["STATUS_RETRIEVAL_ERROR"] },
  },
  {
    id: "status-list-wrong-issuer",
    title:
      "Bitstring status: the status list is signed by a DIFFERENT issuer than the hop → fail-closed deny",
    clauses: ["#revocation-verification (issuer binding)", "#sec-status-availability"],
    hop: hopRevocation,
    list: await signedStatusList({ setBits: [], key: presenterKey, issuer: PRESENTER }),
    documents: { [LIST_URL]: "status-list.ttl" },
    expected: { verified: false, codes: ["STATUS_RETRIEVAL_ERROR"] },
  },
];

// --- presentation-replay cases -------------------------------------------------
const plainHop = await issueAgentAuthorization(
  { principal: ISSUER, agent: PRESENTER, action: "read", target: TARGET },
  issuerKey,
);
const vpOk = await signPresentation(
  { holder: PRESENTER, verifiableCredential: [plainHop] },
  presenterKey,
  { challenge: CHALLENGE, domain: DOMAIN },
);
const vpStale = await signPresentation(
  { holder: PRESENTER, verifiableCredential: [plainHop] },
  presenterKey,
  { challenge: "an-old-challenge", domain: DOMAIN },
);
const vpWrongDomain = await signPresentation(
  { holder: PRESENTER, verifiableCredential: [plainHop] },
  presenterKey,
  { challenge: CHALLENGE, domain: "https://evil.example" },
);

const VP_CASES = [
  {
    id: "presentation-challenge-ok",
    title: "Presentation bound to the verifier's challenge + domain, holder proves control → verified",
    clauses: ["#presentations", "#sec-replay (stolen presentation)"],
    vp: vpOk,
    expected: { verified: true, codes: [] },
  },
  {
    id: "presentation-challenge-mismatch",
    title: "Replayed presentation (bound to an OLD challenge) → deny CHALLENGE_MISMATCH",
    clauses: ["#presentations", "#sec-replay (stolen presentation)"],
    vp: vpStale,
    expected: { verified: false, codes: ["CHALLENGE_MISMATCH"] },
  },
  {
    id: "presentation-domain-mismatch",
    title: "Presentation bound to a DIFFERENT relying party's domain → deny DOMAIN_MISMATCH",
    clauses: ["#presentations", "#sec-replay (stolen presentation)"],
    vp: vpWrongDomain,
    expected: { verified: false, codes: ["DOMAIN_MISMATCH"] },
  },
];

// --- generate + verify ----------------------------------------------------------
const newEntries = [];
let failures = 0;

for (const c of STATUS_CASES) {
  const docs = { "credential.vc.json": stableJson(c.hop) };
  if (c.list !== undefined) docs["status-list.ttl"] = c.list;
  const r = await verifyCredential(c.hop, {
    resolveKey,
    isControlledBy,
    now: new Date(NOW),
    fetch: fixtureFetch(c.documents, { "status-list.ttl": c.list }),
  });
  const actual = { verified: r.verified, codes: r.errors.map((e) => e.code) };
  if (JSON.stringify(actual) !== JSON.stringify(c.expected)) {
    failures++;
    console.error(`MISMATCH ${c.id}: want ${JSON.stringify(c.expected)} got ${JSON.stringify(actual)}`);
    continue;
  }
  const caseJson = {
    id: `agent-authz-credential/${c.id}`,
    title: c.title,
    spec: SPEC,
    clauses: c.clauses,
    operation: "verify-credential-status",
    input: { credential: "credential.vc.json", documents: c.documents, now: NOW },
    expected: c.expected,
    source: SOURCE_STATUS,
    ...(c.note !== undefined && { note: c.note }),
  };
  newEntries.push({ caseId: c.id, caseJson, docs });
  console.log(`agent-authz-credential/${c.id}: ${JSON.stringify(actual)}`);
}

for (const c of VP_CASES) {
  const r = await verifyPresentation(c.vp, {
    resolveKey,
    isControlledBy,
    now: new Date(NOW),
    challenge: CHALLENGE,
    domain: DOMAIN,
  });
  const actual = { verified: r.verified, codes: r.errors.map((e) => e.code) };
  if (JSON.stringify(actual) !== JSON.stringify(c.expected)) {
    failures++;
    console.error(`MISMATCH ${c.id}: want ${JSON.stringify(c.expected)} got ${JSON.stringify(actual)}`);
    continue;
  }
  const caseJson = {
    id: `agent-authz-credential/${c.id}`,
    title: c.title,
    spec: SPEC,
    clauses: c.clauses,
    operation: "verify-presentation-replay",
    input: {
      presentation: "presentation.vp.json",
      challenge: CHALLENGE,
      domain: DOMAIN,
      now: NOW,
    },
    expected: c.expected,
    source: SOURCE_VP,
  };
  newEntries.push({
    caseId: c.id,
    caseJson,
    docs: { "presentation.vp.json": stableJson(c.vp) },
  });
  console.log(`agent-authz-credential/${c.id}: ${JSON.stringify(actual)}`);
}

// Verify-all-first, THEN write (keyring included) — no partial fixtures on failure.
if (failures > 0) {
  console.error(`${failures} mismatches — vectors NOT written`);
  process.exit(1);
}
for (const { name, body } of keyringDocs) {
  writeFixture(
    join(REPO_ROOT, "vectors", "agent-authz-credential", "keyring", `${name}.json`),
    body,
  );
}

// --- merge into the suite manifest (aac-chain.mjs wrote the chain cases) --------
const manifestPath = join(REPO_ROOT, "vectors", "agent-authz-credential", "manifest.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const existingIds = new Set(manifest.cases.map((c) => c.id));
for (const { caseId, caseJson, docs } of newEntries) {
  const rel = writeCase("agent-authz-credential", caseId, caseJson, docs);
  if (existingIds.has(caseJson.id)) continue;
  manifest.cases.push({ id: caseJson.id, path: rel });
  for (const clause of caseJson.clauses) {
    (manifest.clauseIndex[clause] ??= []).push(caseJson.id);
  }
}
manifest.caseCount = manifest.cases.length;
writeFixture(manifestPath, stableJson(manifest));
console.log(
  `agent-authz-credential (status + presentation): ${newEntries.length} cases appended (total ${manifest.caseCount})`,
);
