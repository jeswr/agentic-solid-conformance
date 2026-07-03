// AUTHORED-BY Claude Fable 5
//
// GENERATOR — vectors/odrl-delegation. Consolidates the delegation decision
// matrix from solid-odrl@18df183 test/characterization.test.ts ("characterization:
// delegation decision matrix") plus the prohibition-laundering case from
// accountable-agent-runtime@0aadd46 test/decision-matrix.test.ts, re-expressed at
// the evaluateDelegated layer.
//
// EXTRACTION DISCIPLINE: the chains are the reference fixtures verbatim; every
// expected verdict is captured by EXECUTING the pinned reference implementation
// over the SERIALIZED Turtle (serialize → re-parse → evaluate), so the on-disk
// language-neutral form provably reproduces the reference verdict. Nothing is
// asserted from memory.

import { evaluateDelegated, parsePolicy, policyToTurtle } from "@jeswr/solid-odrl";
import { SuiteManifest, writeCase } from "../lib/emit.mjs";

const SPEC = "https://w3id.org/jeswr/odrl-delegation";
const SOURCE_MATRIX =
  "solid-odrl@18df183 test/characterization.test.ts (delegation decision matrix)";
const SOURCE_RUNTIME =
  "accountable-agent-runtime@0aadd46 test/decision-matrix.test.ts (PROHIBITION LAUNDERING), re-expressed at the evaluateDelegated layer";

// --- the reference fixtures (characterization.test.ts, verbatim) -----------
const OWNER = "https://alice.example/profile/card#me";
const RES = "https://alice.example/notes/private.ttl";
const NOW = "2026-06-16T12:00:00Z";
const AGENT_A = "https://agent-a.example/id#it";
const AGENT_B = "https://agent-b.example/id#it";
const AGENT_C = "https://agent-c.example/id#it";
const ROOT_ID = "https://alice.example/policies/root";
const HOP1_ID = "https://agent-a.example/policies/to-b";
const HOP2_ID = "https://agent-b.example/policies/to-c";
const PAST = "2026-01-01T00:00:00Z";
const DEPTH_2 = {
  constraints: [{ leftOperand: "delegationDepth", operator: "lteq", rightOperand: 2 }],
};
const READ_B = { agent: AGENT_B, action: "read", target: RES };
const READ_C = { agent: AGENT_C, action: "read", target: RES };

const rootPolicy = (grantUse = {}) => ({
  id: ROOT_ID,
  type: "Agreement",
  profile: SPEC,
  assigner: OWNER,
  permissions: [
    { type: "permission", action: "read", target: RES, assignee: AGENT_A },
    { type: "permission", action: "grantUse", target: RES, assignee: AGENT_A, ...grantUse },
  ],
});
const hop1Policy = (overrides = {}) => ({
  id: HOP1_ID,
  type: "Agreement",
  profile: SPEC,
  assigner: AGENT_A,
  assignee: AGENT_B,
  delegatedUnder: ROOT_ID,
  permissions: [{ type: "permission", action: "read", target: RES, assignee: AGENT_B }],
  ...overrides,
});
const hop1WithGrant = () =>
  hop1Policy({
    permissions: [
      { type: "permission", action: "read", target: RES, assignee: AGENT_B },
      { type: "permission", action: "grantUse", target: RES, assignee: AGENT_B },
    ],
  });
const hop2Policy = () => ({
  id: HOP2_ID,
  type: "Agreement",
  profile: SPEC,
  assigner: AGENT_B,
  assignee: AGENT_C,
  delegatedUnder: HOP1_ID,
  permissions: [{ type: "permission", action: "read", target: RES, assignee: AGENT_C }],
});

// PROHIBITION LAUNDERING (runtime matrix, at the delegation layer): the root
// permits distribute to A directly BUT prohibits distribute on the asset; the
// leaf permits B distribute. §6.2: a matched prohibition at any hop fails the
// chain — delegation must never launder a request around an upstream prohibition.
const rootWithProhibition = () => ({
  ...rootPolicy({}),
  permissions: [
    ...rootPolicy({}).permissions,
    { type: "permission", action: "distribute", target: RES, assignee: AGENT_A },
  ],
  prohibitions: [{ type: "prohibition", action: "distribute", target: RES }],
});
const hop1Laundering = () =>
  hop1Policy({
    permissions: [
      { type: "permission", action: "read", target: RES, assignee: AGENT_B },
      { type: "permission", action: "distribute", target: RES, assignee: AGENT_B },
    ],
  });

// The odrld:Revocation statement the revoked case's `revoked` set derives from
// (profile §4.3/§7). A static input DOCUMENT (like a spec example), not code-built RDF.
const REVOCATION_DOC = `@prefix odrld: <https://w3id.org/jeswr/odrl-delegation#>.

<https://alice.example/revocations/r1#it> a odrld:Revocation;
    odrld:revokedPolicy <${HOP1_ID}>.
`;

// --- the case matrix ---------------------------------------------------------
const CASES = [
  {
    id: "valid-1hop",
    title: "valid 1-hop chain → permit",
    clauses: ["§5.1", "§5.2.1-4", "§6.1", "§6 (leaf)"],
    chain: [rootPolicy(), hop1Policy()],
    request: READ_B,
  },
  {
    id: "valid-2hop",
    title: "valid 2-hop chain (root depth 2) → permit",
    clauses: ["§4.1", "§5.2.5", "§6.1"],
    chain: [rootPolicy(DEPTH_2), hop1WithGrant(), hop2Policy()],
    request: READ_C,
  },
  {
    id: "over-broad-deny",
    title: "over-broad hop (delegate granted write the delegator lacks) → deny",
    clauses: ["§6.1"],
    chain: [
      rootPolicy(),
      hop1Policy({
        permissions: [{ type: "permission", action: "write", target: RES, assignee: AGENT_B }],
      }),
    ],
    request: { ...READ_B, action: "write" },
  },
  {
    id: "expired-mid-chain-deny",
    title: "expired mid-chain hop → deny (an expired middle hop invalidates the whole suffix)",
    clauses: ["§7 (expiry)", "§6.1"],
    chain: [
      rootPolicy(DEPTH_2),
      hop1Policy({
        permissions: [
          {
            type: "permission",
            action: "read",
            target: RES,
            assignee: AGENT_B,
            constraints: [{ leftOperand: "dateTime", operator: "lteq", rightOperand: PAST }],
          },
          { type: "permission", action: "grantUse", target: RES, assignee: AGENT_B },
        ],
      }),
      hop2Policy(),
    ],
    request: READ_C,
  },
  {
    id: "cycle-deny",
    title: "cyclic chain (root repeated) → deny (acyclicity)",
    clauses: ["§5.1.2"],
    chain: [rootPolicy(DEPTH_2), hop1WithGrant(), rootPolicy(DEPTH_2)],
    chainFiles: ["chain-0.ttl", "chain-1.ttl", "chain-0.ttl"], // the repeat IS the same document
    request: READ_B,
  },
  {
    id: "depth-exceeded-default-deny",
    title: "depth exceeded: 2 hops under the DEFAULT budget of 1 → deny (fail-closed default)",
    clauses: ["§4.1 (default budget 1)", "§5.2.5"],
    chain: [rootPolicy(), hop1WithGrant(), hop2Policy()],
    request: READ_C,
  },
  {
    id: "depth-exceeded-explicit-deny",
    title: "depth exceeded: 2 hops under an explicit delegationDepth lteq 1 → deny",
    clauses: ["§4.1", "§5.2.5"],
    chain: [
      rootPolicy({
        constraints: [{ leftOperand: "delegationDepth", operator: "lteq", rightOperand: 1 }],
      }),
      hop1WithGrant(),
      hop2Policy(),
    ],
    request: READ_C,
  },
  {
    id: "nextpolicy-mandated-permit",
    title: "nextPolicy duty: the mandated hop is the one granted, in-scope request → permit",
    clauses: ["§5.2.6"],
    chain: [rootPolicy({ duties: [{ action: "nextPolicy", target: HOP1_ID }] }), hop1Policy()],
    request: READ_B,
  },
  {
    id: "nextpolicy-out-of-scope-deny",
    title: "nextPolicy duty: out-of-scope request against the mandated hop → deny",
    clauses: ["§5.2.6", "§6.1"],
    chain: [rootPolicy({ duties: [{ action: "nextPolicy", target: HOP1_ID }] }), hop1Policy()],
    request: { ...READ_B, action: "write" },
  },
  {
    id: "nextpolicy-violated-deny",
    title: "nextPolicy duty violated (a different policy was delegated) → deny",
    clauses: ["§5.2.6"],
    chain: [rootPolicy({ duties: [{ action: "nextPolicy", target: HOP2_ID }] }), hop1Policy()],
    request: READ_B,
  },
  {
    id: "revoked-deny",
    title: "revoked hop (odrld:Revocation → the revoked set) → deny",
    clauses: ["§4.3", "§5.1.3", "§7 (revocation)"],
    chain: [rootPolicy(), hop1Policy()],
    request: READ_B,
    revoked: [HOP1_ID],
    extraDocs: { "revocation.ttl": REVOCATION_DOC },
    note:
      "revocation.ttl is the published odrld:Revocation statement; `revoked` is exactly the " +
      "set a caller derives from its odrld:revokedPolicy objects (profile §7 — the evaluator " +
      "itself performs no I/O).",
  },
  {
    id: "use-does-not-grant-delegation-deny",
    title:
      "profile restriction: a bare odrl:use permission does NOT authorise delegation (grantUse must be literal) → deny",
    clauses: ["§3.2", "§5.2.4"],
    chain: [
      {
        ...rootPolicy({}),
        permissions: [
          { type: "permission", action: "read", target: RES, assignee: AGENT_A },
          { type: "permission", action: "use", target: RES, assignee: AGENT_A },
        ],
      },
      hop1Policy(),
    ],
    request: READ_B,
    note:
      "ODRL 2.2 marks grantUse as 'Included In: use'; followed literally, every use-grantee " +
      "could mint downstream grants (privilege escalation). The profile RESTRICTS the " +
      "hierarchy: delegation authority MUST be granted by a rule whose action is literally " +
      "odrl:grantUse.",
  },
  {
    id: "prohibition-laundering-deny",
    title:
      "prohibition laundering: root PERMITS distribute to its own delegate but PROHIBITS it on the asset; the leaf re-grants distribute → deny",
    clauses: ["§6.2 (strict prohibitions)"],
    chain: [rootWithProhibition(), hop1Laundering()],
    request: { agent: AGENT_B, action: "distribute", target: RES },
    source: SOURCE_RUNTIME,
  },
];

// --- generate ----------------------------------------------------------------
const manifest = new SuiteManifest({
  suite: "odrl-delegation",
  spec: SPEC,
  description:
    "evaluate-delegated-chain vectors for the ODRL Agent-Delegation Profile: the delegation decision matrix (valid 1-/2-hop permits; over-broad, expired-mid-chain, cyclic, depth-exceeded, nextPolicy-violated, revoked and prohibition-laundering denies).",
});

let failures = 0;
for (const c of CASES) {
  // 1. Serialize each DISTINCT policy of the chain to Turtle (the normative RDF form).
  const files = new Map(); // filename → { turtle, policyId }
  const chainRefs = [];
  for (let i = 0; i < c.chain.length; i++) {
    const name = c.chainFiles?.[i] ?? `chain-${i}.ttl`;
    chainRefs.push(name);
    if (!files.has(name)) {
      files.set(name, await policyToTurtle(c.chain[i]));
    }
  }

  // 2. RE-PARSE the serialized Turtle and evaluate — the verdict is extracted from
  //    the reference implementation over the exact bytes shipped in the vector.
  const parsedChain = [];
  for (const name of chainRefs) {
    const p = await parsePolicy(files.get(name));
    if (p === undefined) throw new Error(`${c.id}: ${name} did not re-parse to a policy`);
    parsedChain.push(p);
  }
  const result = evaluateDelegated(parsedChain, c.request, {
    now: new Date(NOW),
    ...(c.revoked !== undefined && { revoked: c.revoked }),
  });

  // 3. Sanity: the serialized-form verdict must equal the in-memory-form verdict
  //    (otherwise the Turtle projection lost something material).
  const direct = evaluateDelegated(c.chain, c.request, {
    now: new Date(NOW),
    ...(c.revoked !== undefined && { revoked: c.revoked }),
  });
  if (direct.decision !== result.decision) {
    failures++;
    console.error(
      `MISMATCH ${c.id}: in-memory=${direct.decision} serialized=${result.decision}`,
    );
    continue;
  }

  const caseJson = {
    id: `odrl-delegation/${c.id}`,
    title: c.title,
    spec: SPEC,
    clauses: c.clauses,
    operation: "evaluate-delegated-chain",
    input: {
      chain: chainRefs,
      request: c.request,
      now: NOW,
      revoked: c.revoked ?? [],
    },
    expected: { decision: result.decision },
    source: c.source ?? SOURCE_MATRIX,
    ...(c.note !== undefined && { note: c.note }),
  };
  const rel = writeCase("odrl-delegation", c.id, caseJson, {
    ...Object.fromEntries(files),
    ...(c.extraDocs ?? {}),
  });
  manifest.add(caseJson, rel);
  console.log(`odrl-delegation/${c.id}: ${result.decision}`);
}

if (failures > 0) {
  console.error(`${failures} serialization mismatches — vectors NOT trustworthy`);
  process.exit(1);
}
manifest.write();
console.log(`odrl-delegation: ${CASES.length} cases written`);
