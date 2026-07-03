// AUTHORED-BY Claude Fable 5
//
// GENERATOR — vectors/agent-authz-credential, the POLICY-CONTENT BINDING sub-suite
// (AAC #policy-binding + #verification step 1): a credential's svc:policy MUST be
// bound by CONTENT — embedded (accepted) or by-reference-with-digest (fetched
// octets verified against the SIGNED digest); a bare digest-less IRI, a digest
// mismatch, or an unreachable policy document → POLICY_INTEGRITY.
//
// Extracted from solid-vc@d6b4e34 test/policy-binding.test.ts by executing
// resolveBoundPolicy over the serialized fixtures. Appends to the
// agent-authz-credential manifest.

import { createHash, subtle } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  base58btcEncode,
  generateKeyPairForSuite,
  issueAgentAuthorization,
  resolveBoundPolicy,
} from "@jeswr/solid-vc";
import { REPO_ROOT, stableJson, writeCase, writeFixture } from "../lib/emit.mjs";

const SPEC = "https://github.com/jeswr/agent-authz-credential-spec";
const SOURCE =
  "solid-vc@d6b4e34 (feat/mtr4-agent-authz-builder-followups) test/policy-binding.test.ts";

const ISSUER = "https://binding-issuer.example/org#id";
const ISSUER_VM = "https://binding-issuer.example/keys#k1";
const AGENT = "https://binding-agent.example/agents/a#it";
const POLICY_URL = "https://binding-issuer.example/policies/p1.ttl";
const POLICY_BODY =
  "<https://binding-issuer.example/policies/p1.ttl#agreement> a <http://www.w3.org/ns/odrl/2/Agreement> .\n";
const POLICY_OCTETS = new TextEncoder().encode(POLICY_BODY);
const TAMPERED_BODY = `${POLICY_BODY}# swapped after signing\n`;

const key = await generateKeyPairForSuite(ISSUER_VM, "Ed25519");

// keyring controller doc (the binding fixtures are signature-valid credentials too)
{
  const jwk = await subtle.exportKey("jwk", key.publicKey);
  delete jwk.key_ops;
  delete jwk.ext;
  const raw = Buffer.from(jwk.x, "base64url");
  writeFixture(
    join(REPO_ROOT, "vectors", "agent-authz-credential", "keyring", "binding-issuer.json"),
    stableJson({
      "@context": ["https://www.w3.org/ns/cid/v1"],
      id: ISSUER,
      verificationMethod: [
        {
          id: ISSUER_VM,
          type: "Multikey",
          controller: ISSUER,
          publicKeyMultibase: base58btcEncode(new Uint8Array([0xed, 0x01, ...raw])),
          publicKeyJwk: jwk,
        },
      ],
      assertionMethod: [ISSUER_VM],
    }),
  );
}

const BASE = { principal: ISSUER, agent: AGENT, action: "read" };
const sri = `sha256-${createHash("sha256").update(POLICY_OCTETS).digest("base64")}`;

const vcEmbedded = await issueAgentAuthorization(
  { ...BASE, embeddedPolicy: { "http://www.w3.org/ns/odrl/2/uid": POLICY_URL } },
  key,
);
const vcBare = await issueAgentAuthorization({ ...BASE, policy: POLICY_URL }, key);
const vcDigest = await issueAgentAuthorization(
  { ...BASE, policy: POLICY_URL, policyDigest: { digestSRI: sri } },
  key,
);

const CASES = [
  {
    id: "binding-embedded-accept",
    title: "policy binding: an EMBEDDED policy graph (signed inline) is accepted",
    clauses: ["#policy-binding (embedded)", "#verification (step 1)"],
    vc: vcEmbedded,
    documents: {},
    expected: { ok: true, form: "embedded", codes: [] },
  },
  {
    id: "binding-bare-iri-reject",
    title: "policy binding: a BARE digest-less svc:policy IRI MUST be rejected (binds nothing)",
    clauses: ["#policy-binding (bare IRI rejected)", "#verification (step 1)"],
    vc: vcBare,
    documents: { [POLICY_URL]: "policy.ttl" },
    docs: { "policy.ttl": POLICY_BODY },
    expected: { ok: false, codes: ["POLICY_INTEGRITY"] },
  },
  {
    id: "binding-digest-match-accept",
    title: "policy binding: a reference whose fetched octets match the signed digestSRI is accepted",
    clauses: ["#policy-binding (relatedResource digest)", "#verification (step 1)"],
    vc: vcDigest,
    documents: { [POLICY_URL]: "policy.ttl" },
    docs: { "policy.ttl": POLICY_BODY },
    expected: { ok: true, form: "reference", codes: [] },
  },
  {
    id: "binding-digest-mismatch-reject",
    title: "policy binding: fetched octets that DO NOT match the signed digest MUST be rejected",
    clauses: ["#policy-binding (digest mismatch)", "#verification (step 1)"],
    vc: vcDigest,
    documents: { [POLICY_URL]: "policy-tampered.ttl" },
    docs: { "policy-tampered.ttl": TAMPERED_BODY },
    expected: { ok: false, codes: ["POLICY_INTEGRITY"] },
  },
  {
    id: "binding-unreachable-reject",
    title: "policy binding: an unreachable policy document (404) MUST be rejected (fail closed)",
    clauses: ["#policy-binding (retrieval failure)", "#verification (step 1)"],
    vc: vcDigest,
    documents: { [POLICY_URL]: { status: 404 } },
    expected: { ok: false, codes: ["POLICY_INTEGRITY"] },
  },
];

function fixtureFetch(documents, bodies) {
  return async (url) => {
    const entry = documents[url];
    if (entry === undefined || typeof entry === "object") {
      const status = typeof entry === "object" ? entry.status : 404;
      return {
        ok: false,
        status,
        headers: { get: () => null },
        text: async () => "",
        arrayBuffer: async () => new ArrayBuffer(0),
      };
    }
    const octets = new TextEncoder().encode(bodies[entry]);
    return {
      ok: true,
      status: 200,
      headers: { get: (n) => (n.toLowerCase() === "content-type" ? "text/turtle" : null) },
      text: async () => bodies[entry],
      arrayBuffer: async () => octets.buffer,
    };
  };
}

const newEntries = [];
let failures = 0;
for (const c of CASES) {
  const r = await resolveBoundPolicy(c.vc, {
    ...(Object.keys(c.documents).length > 0 && {
      fetch: fixtureFetch(c.documents, c.docs ?? {}),
    }),
  });
  const actual = {
    ok: r.errors.length === 0,
    ...(r.policy?.form !== undefined && { form: r.policy.form }),
    codes: r.errors.map((e) => e.code),
  };
  if (JSON.stringify(actual) !== JSON.stringify(c.expected)) {
    failures++;
    console.error(
      `MISMATCH ${c.id}: want ${JSON.stringify(c.expected)} got ${JSON.stringify(actual)}`,
    );
    continue;
  }
  const caseJson = {
    id: `agent-authz-credential/${c.id}`,
    title: c.title,
    spec: SPEC,
    clauses: c.clauses,
    operation: "resolve-bound-policy",
    input: { credential: "credential.vc.json", documents: c.documents },
    expected: c.expected,
    source: SOURCE,
  };
  const rel = writeCase("agent-authz-credential", c.id, caseJson, {
    "credential.vc.json": stableJson(c.vc),
    ...(c.docs ?? {}),
  });
  newEntries.push({ caseJson, rel });
  console.log(`agent-authz-credential/${c.id}: ${JSON.stringify(actual)}`);
}

if (failures > 0) {
  console.error(`${failures} mismatches — manifest NOT updated`);
  process.exit(1);
}

const manifestPath = join(REPO_ROOT, "vectors", "agent-authz-credential", "manifest.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const existingIds = new Set(manifest.cases.map((c) => c.id));
for (const { caseJson, rel } of newEntries) {
  if (existingIds.has(caseJson.id)) continue;
  manifest.cases.push({ id: caseJson.id, path: rel });
  for (const clause of caseJson.clauses) {
    (manifest.clauseIndex[clause] ??= []).push(caseJson.id);
  }
}
manifest.caseCount = manifest.cases.length;
writeFixture(manifestPath, stableJson(manifest));
console.log(
  `agent-authz-credential (policy binding): ${newEntries.length} cases appended (total ${manifest.caseCount})`,
);
