// AUTHORED-BY Claude Fable 5
//
// GENERATOR — vectors/a2a-rdf. Pins the deterministic core of the A2A RDF
// extension (https://w3id.org/jeswr/a2a-rdf/v1):
//
//   rdfc10-hash / verify-pd-pin — §Content addressing: the RDFC-1.0 canonical
//     N-Quads → SHA-256 protocol hash of the spec's execution-verified
//     grant-access Protocol Document example (sha256:4af1e70e…), plus the
//     tampered-body rejection rule, plus the LWS-composition
//     representation-stability pair (jeswr/lws-spec docs/alignment/a2a-rdf.md §3):
//     the hash pins the parsed GRAPH, not bytes, so an rdf-1-faithful JSON-LD
//     rendering (JLWS RDF Content Transformation Profile: derived representations
//     are graph-isomorphic) matches the Turtle-derived pin, and a one-triple graph
//     delta breaks it in any serialization.
//   decode-handshake — §Upgrade offer / §Upgrade response: strict payload
//     validation (a malformed required/accept flag MUST be rejected, never
//     coerced).
//   may-downgrade-to-nl — §The no-silent-downgrade rule: the full decision table.
//   validate-intent — §Message-content binding: SHACL validation of intent
//     graphs against the PD's request shape.
//
// Verdicts extracted by executing @jeswr/solid-a2a@e5ff315 (0.2.0 — the
// RDFC-1.0-aligned codec; = the SOURCE constant and tools/package.json pin); the
// PD hash is additionally hard-asserted against the spec's published example value.

import { parseRdf } from "@jeswr/fetch-rdf";
import {
  canonicalNQuads,
  decodeUpgradeOffer,
  decodeUpgradeResponse,
  hashQuads,
  mayDowngradeToNl,
  validateIntent,
  verifyProtocolDocument,
} from "@jeswr/solid-a2a";
import { SuiteManifest, writeCase } from "../lib/emit.mjs";

const SPEC = "https://w3id.org/jeswr/a2a-rdf/v1";
const SOURCE = "@jeswr/solid-a2a@e5ff315 (0.2.0); spec example: a2a-rdf-extension index.html";
// The spec's published example hash (§Agent Card declaration + §Upgrade offer).
const EXPECTED_HASH = "sha256:4af1e70e42283872cbc0dd3a5eeaa1bd86adda728c993447bed8930d990ab509";
const PD_SOURCE = "https://alice.pod.example/protocols/grant-access";

// The grant-access Protocol Document — the spec's §Protocol Documents example, verbatim.
const PD_TTL = `@prefix a2a: <https://w3id.org/jeswr/a2a#>.
@prefix schema: <https://schema.org/>.
@prefix sh: <http://www.w3.org/ns/shacl#>.
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>.
@prefix dcterms: <http://purl.org/dc/terms/>.

<https://alice.pod.example/protocols/grant-access> a a2a:ProtocolDocument;
    dcterms:title "Grant access";
    dcterms:hasVersion "1.0.0";
    a2a:requestShape a2a:GrantIntentShape.
a2a:GrantIntentShape a sh:NodeShape;
    sh:targetClass a2a:Intent;
    sh:property [ a sh:PropertyShape;
        sh:path a2a:action; sh:minCount 1; sh:maxCount 1; sh:name "action";
        sh:node [ a sh:NodeShape;
            sh:property
                [ a sh:PropertyShape; sh:path rdf:type; sh:minCount 1; sh:hasValue a2a:GrantAction ],
                [ a sh:PropertyShape; sh:path schema:object; sh:minCount 1; sh:name "target"; sh:nodeKind sh:IRI ],
                [ a sh:PropertyShape; sh:path schema:recipient; sh:minCount 1; sh:name "recipient"; sh:nodeKind sh:IRI ],
                [ a sh:PropertyShape; sh:path a2a:mode; sh:minCount 1; sh:name "mode"; sh:nodeKind sh:IRI ] ] ].
`;

// A tampered copy (title changed) — same shape, different content, different hash.
const PD_TAMPERED_TTL = PD_TTL.replace('"Grant access"', '"Grant access (tampered)"');

// --- LWS-composition fixtures: the SAME PD graph as expanded JSON-LD -------------
// An rdf-1-faithful rendering (JLWS RDF Content Transformation Profile,
// rdf-transform.html §Transformation semantics: a derived representation encodes a
// graph ISOMORPHIC to the authoritative one — no triples added, none removed).
// Expanded form, context-free — deliberately: the rdf-1 contract's own
// no-remote-context discipline. Authored as an alternative serialization of PD_TTL
// (the same epistemic status as the hand-authored PD_TTL beside it) and
// HARD-ASSERTED below to canonicalize to byte-identical RDFC-1.0 N-Quads, which is
// what makes the pin representation-stable.
const A2A_NS = "https://w3id.org/jeswr/a2a#";
const SH_NS = "http://www.w3.org/ns/shacl#";
const DCT_NS = "http://purl.org/dc/terms/";
const propertyShape = (path, extra = {}) => ({
  "@type": [`${SH_NS}PropertyShape`],
  [`${SH_NS}path`]: [{ "@id": path }],
  [`${SH_NS}minCount`]: [{ "@value": 1 }],
  ...extra,
});
const PD_JSONLD_DOC = [
  {
    "@id": PD_SOURCE,
    "@type": [`${A2A_NS}ProtocolDocument`],
    [`${DCT_NS}title`]: [{ "@value": "Grant access" }],
    [`${DCT_NS}hasVersion`]: [{ "@value": "1.0.0" }],
    [`${A2A_NS}requestShape`]: [{ "@id": `${A2A_NS}GrantIntentShape` }],
  },
  {
    "@id": `${A2A_NS}GrantIntentShape`,
    "@type": [`${SH_NS}NodeShape`],
    [`${SH_NS}targetClass`]: [{ "@id": `${A2A_NS}Intent` }],
    [`${SH_NS}property`]: [
      {
        ...propertyShape(`${A2A_NS}action`),
        [`${SH_NS}maxCount`]: [{ "@value": 1 }],
        [`${SH_NS}name`]: [{ "@value": "action" }],
        [`${SH_NS}node`]: [
          {
            "@type": [`${SH_NS}NodeShape`],
            [`${SH_NS}property`]: [
              propertyShape("http://www.w3.org/1999/02/22-rdf-syntax-ns#type", {
                [`${SH_NS}hasValue`]: [{ "@id": `${A2A_NS}GrantAction` }],
              }),
              propertyShape("https://schema.org/object", {
                [`${SH_NS}name`]: [{ "@value": "target" }],
                [`${SH_NS}nodeKind`]: [{ "@id": `${SH_NS}IRI` }],
              }),
              propertyShape("https://schema.org/recipient", {
                [`${SH_NS}name`]: [{ "@value": "recipient" }],
                [`${SH_NS}nodeKind`]: [{ "@id": `${SH_NS}IRI` }],
              }),
              propertyShape(`${A2A_NS}mode`, {
                [`${SH_NS}name`]: [{ "@value": "mode" }],
                [`${SH_NS}nodeKind`]: [{ "@id": `${SH_NS}IRI` }],
              }),
            ],
          },
        ],
      },
    ],
  },
];
const PD_JSONLD = `${JSON.stringify(PD_JSONLD_DOC, null, 2)}\n`;

// A one-triple GRAPH delta of the same rendering: one added dcterms:description.
// Everything else identical — rejecting this proves acceptance above comes from
// graph identity, not lenient JSON-LD handling.
const PD_JSONLD_GRAPH_CHANGE_DOC = structuredClone(PD_JSONLD_DOC);
PD_JSONLD_GRAPH_CHANGE_DOC[0][`${DCT_NS}description`] = [
  { "@value": "Grants a recipient access to a resource." },
];
const PD_JSONLD_GRAPH_CHANGE = `${JSON.stringify(PD_JSONLD_GRAPH_CHANGE_DOC, null, 2)}\n`;

// The spec's §Message-content binding conforming intent example, verbatim.
const INTENT_VALID_TTL = `@prefix a2a: <https://w3id.org/jeswr/a2a#>.
@prefix schema: <https://schema.org/>.
@prefix acl: <http://www.w3.org/ns/auth/acl#>.

<urn:a2a:intent:kxs8cv> a a2a:Intent;
    a2a:action [ a a2a:GrantAction;
        schema:object <https://alice.pod.example/notes/>;
        schema:recipient <https://bob.example/profile#me>;
        a2a:mode acl:Read, acl:Write ].
`;

// Non-conforming: the action node carries NO a2a:mode (sh:minCount 1 violated).
const INTENT_MISSING_MODE_TTL = `@prefix a2a: <https://w3id.org/jeswr/a2a#>.
@prefix schema: <https://schema.org/>.

<urn:a2a:intent:kxs8cw> a a2a:Intent;
    a2a:action [ a a2a:GrantAction;
        schema:object <https://alice.pod.example/notes/>;
        schema:recipient <https://bob.example/profile#me> ].
`;

const OFFER = {
  kind: "upgrade-offer",
  protocolHash: EXPECTED_HASH,
  protocolSource: PD_SOURCE,
  required: true,
  protocolName: "Grant access",
};
const OFFER_OPTIONAL = { ...OFFER, required: false };

const quadsOf = async (ttl) => [...(await parseRdf(ttl, "text/turtle", {}))];

// --- compute + hard-assert the reference values --------------------------------
const pdQuads = await quadsOf(PD_TTL);
const hash = await hashQuads(pdQuads);
if (hash !== EXPECTED_HASH) {
  console.error(`PD hash drift: computed ${hash}, spec pins ${EXPECTED_HASH}`);
  process.exit(1);
}
const canonical = await canonicalNQuads(pdQuads);
const tamperedOk = await verifyProtocolDocument(PD_TAMPERED_TTL, EXPECTED_HASH);
if (tamperedOk !== false) {
  console.error("tampered PD unexpectedly verified against the pin");
  process.exit(1);
}
// LWS-composition asserts: the JSON-LD rendering IS the same graph (byte-identical
// RDFC-1.0 canonical form) and verifies against the Turtle-derived pin …
const jsonldQuads = [...(await parseRdf(PD_JSONLD, "application/ld+json", {}))];
if ((await canonicalNQuads(jsonldQuads)) !== canonical) {
  console.error("PD_JSONLD is not graph-isomorphic to PD_TTL (canonical bytes differ)");
  process.exit(1);
}
if ((await verifyProtocolDocument(PD_JSONLD, EXPECTED_HASH, "application/ld+json")) !== true) {
  console.error("rdf-1-faithful JSON-LD rendering failed the pin");
  process.exit(1);
}
// … and the graph-change fixture differs by EXACTLY one triple and fails the pin.
const changedQuads = [...(await parseRdf(PD_JSONLD_GRAPH_CHANGE, "application/ld+json", {}))];
if (changedQuads.length !== pdQuads.length + 1) {
  console.error(
    `graph-change fixture must differ by exactly one triple (got ${changedQuads.length} vs ${pdQuads.length})`,
  );
  process.exit(1);
}
if (
  (await verifyProtocolDocument(PD_JSONLD_GRAPH_CHANGE, EXPECTED_HASH, "application/ld+json")) !==
  false
) {
  console.error("graph-changed JSON-LD unexpectedly verified against the pin");
  process.exit(1);
}
const validReport = await validateIntent(await quadsOf(INTENT_VALID_TTL), pdQuads);
const invalidReport = await validateIntent(await quadsOf(INTENT_MISSING_MODE_TTL), pdQuads);
if (validReport.conforms !== true || invalidReport.conforms !== false) {
  console.error(
    `intent validation drift: valid=${validReport.conforms} invalid=${invalidReport.conforms}`,
  );
  process.exit(1);
}

// --- the case matrix ------------------------------------------------------------
const CASES = [
  {
    id: "pd-hash-grant-access",
    title: "RDFC-1.0 protocol hash of the grant-access Protocol Document (the spec example)",
    clauses: ["§Content addressing (steps 1-3)"],
    operation: "rdfc10-hash",
    docs: { "protocol-document.ttl": PD_TTL, "canonical.nq": canonical },
    input: { graph: "protocol-document.ttl" },
    expected: { hash: EXPECTED_HASH, canonical: "canonical.nq" },
    note:
      "expected.canonical names the byte-exact RDFC-1.0 canonical N-Quads file (LF line " +
      "endings) so a failing implementation can localise the drift: wrong canonical bytes = " +
      "the canonicalization step; right bytes + wrong hash = the digest/rendering step.",
  },
  {
    id: "pd-pin-match",
    title: "verify-pd-pin: the fetched PD body matches the pinned hash → accept",
    clauses: ["§Content addressing (recompute on fetch)"],
    operation: "verify-pd-pin",
    docs: { "protocol-document.ttl": PD_TTL },
    input: { body: "protocol-document.ttl", pinnedHash: EXPECTED_HASH },
    expected: { ok: true },
  },
  {
    id: "pd-pin-mismatch",
    title: "verify-pd-pin: a tampered PD body MUST be rejected against the pin",
    clauses: ["§Content addressing (recompute on fetch; the hash is the trust anchor)"],
    operation: "verify-pd-pin",
    docs: { "protocol-document-tampered.ttl": PD_TAMPERED_TTL },
    input: { body: "protocol-document-tampered.ttl", pinnedHash: EXPECTED_HASH },
    expected: { ok: false },
  },
  {
    id: "pd-hash-stable-across-representations",
    title:
      "verify-pd-pin: the SAME PD graph as an rdf-1-faithful JSON-LD rendering matches the Turtle-derived pin (representation-stable pinning)",
    clauses: ["§Content addressing (steps 1-3 — the hash pins the graph, not its serialization)"],
    operation: "verify-pd-pin",
    docs: { "protocol-document.jsonld": PD_JSONLD },
    input: {
      body: "protocol-document.jsonld",
      mediaType: "application/ld+json",
      pinnedHash: EXPECTED_HASH,
    },
    expected: { ok: true },
    note:
      "LWS composition (jeswr/lws-spec docs/alignment/a2a-rdf.md §3): under the JLWS RDF " +
      "Content Transformation Profile's rdf-1 contract (rdf-transform.html §Transformation " +
      "semantics — derived representations are graph-isomorphic) a PD stored as Turtle and " +
      "served as JSON-LD pins identically, because the protocol hash is computed over the " +
      "parsed graph. This fixture is asserted at generation time to canonicalize to the SAME " +
      "RDFC-1.0 bytes as pd-hash-grant-access/canonical.nq; the Turtle half of the pair is " +
      "pd-pin-match (same pinned hash).",
  },
  {
    id: "pd-hash-rejects-graph-change",
    title:
      "verify-pd-pin: a JSON-LD rendering whose graph differs by ONE added triple MUST be rejected — content pins regardless of serialization",
    clauses: ["§Content addressing (recompute on fetch; the hash is the trust anchor)"],
    operation: "verify-pd-pin",
    docs: { "protocol-document-graph-change.jsonld": PD_JSONLD_GRAPH_CHANGE },
    input: {
      body: "protocol-document-graph-change.jsonld",
      mediaType: "application/ld+json",
      pinnedHash: EXPECTED_HASH,
    },
    expected: { ok: false },
    note:
      "The fixture is the representation-stable JSON-LD PD plus exactly one added " +
      "dcterms:description triple (asserted at generation time). Rejecting it proves the " +
      "acceptance in pd-hash-stable-across-representations comes from graph identity, not " +
      "from lenient JSON-LD handling.",
  },
  {
    id: "decode-offer-ok",
    title: "decode-handshake: a well-formed upgrade-offer decodes",
    clauses: ["§Upgrade offer"],
    operation: "decode-handshake",
    input: { payload: OFFER },
    expected: { ok: true },
  },
  {
    id: "decode-offer-malformed-required",
    title:
      "decode-handshake: an offer whose required is a STRING MUST be rejected (never coerced)",
    clauses: ["§Upgrade offer (required: malformed flag MUST NOT be coerced)"],
    operation: "decode-handshake",
    input: { payload: { ...OFFER, required: "true" } },
    expected: { ok: false },
  },
  {
    id: "decode-response-ok",
    title: "decode-handshake: a well-formed upgrade-response decodes",
    clauses: ["§Upgrade response"],
    operation: "decode-handshake",
    input: { payload: { kind: "upgrade-response", protocolHash: EXPECTED_HASH, accept: true } },
    expected: { ok: true },
  },
  {
    id: "decode-response-missing-accept",
    title:
      "decode-handshake: a response with NO accept member MUST be rejected (it MUST NOT default to false)",
    clauses: ["§Upgrade response (accept: MUST NOT default)"],
    operation: "decode-handshake",
    input: { payload: { kind: "upgrade-response", protocolHash: EXPECTED_HASH } },
    expected: { ok: false },
  },
  {
    id: "decode-response-nonboolean-accept",
    title: "decode-handshake: a response whose accept is a STRING MUST be rejected",
    clauses: ["§Upgrade response (accept: not a JSON boolean → reject)"],
    operation: "decode-handshake",
    input: {
      payload: { kind: "upgrade-response", protocolHash: EXPECTED_HASH, accept: "false" },
    },
    expected: { ok: false },
  },
  {
    id: "downgrade-accepted",
    title: "no-silent-downgrade: peer ACCEPTED → proceed in validated RDF, NL not used",
    clauses: ["§The no-silent-downgrade rule (condition 3)"],
    operation: "may-downgrade-to-nl",
    input: {
      offer: OFFER,
      response: { kind: "upgrade-response", protocolHash: EXPECTED_HASH, accept: true },
    },
    expected: { downgrade: false },
  },
  {
    id: "downgrade-refused-required",
    title:
      "no-silent-downgrade: a REQUIRED (security-bearing) offer declined → the exchange is aborted, NEVER retried in prose",
    clauses: ["§The no-silent-downgrade rule (condition 2)"],
    operation: "may-downgrade-to-nl",
    input: {
      offer: OFFER,
      response: {
        kind: "upgrade-response",
        protocolHash: EXPECTED_HASH,
        accept: false,
        reason: "unsupported",
      },
    },
    expected: { downgrade: false },
  },
  {
    id: "downgrade-allowed-optional",
    title: "no-silent-downgrade: a NON-required offer declined about the SAME hash → NL fallback allowed",
    clauses: ["§The no-silent-downgrade rule (all three conditions hold)"],
    operation: "may-downgrade-to-nl",
    input: {
      offer: OFFER_OPTIONAL,
      response: { kind: "upgrade-response", protocolHash: EXPECTED_HASH, accept: false },
    },
    expected: { downgrade: true },
  },
  {
    id: "downgrade-unrelated-response",
    title:
      "no-silent-downgrade: a decline about a DIFFERENT protocolHash answers nothing → fail closed",
    clauses: ["§The no-silent-downgrade rule (condition 1)"],
    operation: "may-downgrade-to-nl",
    input: {
      offer: OFFER_OPTIONAL,
      response: {
        kind: "upgrade-response",
        protocolHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        accept: false,
      },
    },
    expected: { downgrade: false },
  },
  {
    id: "intent-valid",
    title: "validate-intent: the spec's conforming grant intent validates against the PD shape",
    clauses: ["§Message-content binding (mandatory pre-action validation)"],
    operation: "validate-intent",
    docs: { "intent.ttl": INTENT_VALID_TTL, "protocol-document.ttl": PD_TTL },
    input: { dataGraph: "intent.ttl", shapesGraph: "protocol-document.ttl" },
    expected: { conforms: true },
  },
  {
    id: "intent-missing-mode",
    title: "validate-intent: an intent missing a2a:mode (sh:minCount 1) does NOT conform",
    clauses: ["§Message-content binding (mandatory pre-action validation)"],
    operation: "validate-intent",
    docs: { "intent.ttl": INTENT_MISSING_MODE_TTL, "protocol-document.ttl": PD_TTL },
    input: { dataGraph: "intent.ttl", shapesGraph: "protocol-document.ttl" },
    expected: { conforms: false },
  },
];

// --- verify decode/downgrade verdicts against the reference codec ---------------
for (const c of CASES) {
  if (c.operation === "decode-handshake") {
    let ok = true;
    try {
      const p = c.input.payload;
      if (p.kind === "upgrade-offer") decodeUpgradeOffer(p);
      else decodeUpgradeResponse(p);
    } catch {
      ok = false;
    }
    if (ok !== c.expected.ok) {
      console.error(`decode drift on ${c.id}: got ok=${ok}`);
      process.exit(1);
    }
  }
  if (c.operation === "may-downgrade-to-nl") {
    const downgrade = mayDowngradeToNl(
      decodeUpgradeOffer(c.input.offer),
      decodeUpgradeResponse(c.input.response),
    );
    if (downgrade !== c.expected.downgrade) {
      console.error(`downgrade drift on ${c.id}: got ${downgrade}`);
      process.exit(1);
    }
  }
}

// --- write -----------------------------------------------------------------------
const manifest = new SuiteManifest({
  suite: "a2a-rdf",
  spec: SPEC,
  description:
    "Vectors for the A2A RDF extension: the RDFC-1.0 protocol hash of the spec's grant-access Protocol Document (+ canonical N-Quads), pin verification accept/reject, representation-stable pinning across an rdf-1-faithful Turtle/JSON-LD pair (the LWS composition), strict handshake payload decoding, the full no-silent-downgrade decision table, and SHACL intent validation.",
});
for (const c of CASES) {
  const caseJson = {
    id: `a2a-rdf/${c.id}`,
    title: c.title,
    spec: SPEC,
    clauses: c.clauses,
    operation: c.operation,
    input: c.input,
    expected: c.expected,
    source: SOURCE,
    ...(c.note !== undefined && { note: c.note }),
  };
  const rel = writeCase("a2a-rdf", c.id, caseJson, c.docs ?? {});
  manifest.add(caseJson, rel);
  console.log(`a2a-rdf/${c.id}`);
}
manifest.write();
console.log(`a2a-rdf: ${CASES.length} cases written (hash ${hash})`);
