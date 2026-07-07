// AUTHORED-BY Claude Fable 5
//
// Reads a spec-companion (jeswr/spec-companion `spec.statements.ttl`) and inverts
// its `spec:testCase` links into the case -> statement-id map this suite needs to
// migrate `case.json.clauses` (brittle section strings) to stable companion
// statement ids (DESIGN §7 of jeswr/spec-companion). RDF is parsed with the
// suite's sanctioned parser (@jeswr/fetch-rdf `parseRdf`) — never a bespoke parser.
//
// The companion is the AUTHORITY: it already carries, per statement, the vector
// cases that exercise it (`spec:testCase vec:<case-slug>`). Inverting that gives a
// provably companion-grounded, bidirectionally-consistent case -> statements map.

import { readFileSync } from "node:fs";
import { parseRdf } from "@jeswr/fetch-rdf";
import { STATEMENT_ID_RE } from "./statement-id.mjs";

const SPEC = "http://www.w3.org/ns/spec#";
const DCT = "http://purl.org/dc/terms/";
const SC = "https://w3id.org/jeswr/spec-companion#";

export { STATEMENT_ID_RE };

/**
 * Parse a companion Turtle file and return:
 *   { companionOf, specVersion,
 *     caseToStatements: Map<caseSlug, Set<statementId>>,
 *     statementToCases: Map<statementId, Set<caseSlug>>,
 *     statementIds: Set<statementId> }
 * where caseSlug is the vector case slug (the directory name, e.g. "happy" or
 * "pd-pin-match") as pinned by the companion's `spec:testCase` IRIs, and
 * statementId is the statement's `dcterms:identifier` literal.
 *
 * @param {string} file  path to the companion `spec.statements.ttl`
 * @param {string} expectedSuite  the vector suite the companion's cases must live
 *   under (e.g. "a2a-rdf"); a `spec:testCase` IRI pointing at any other suite is a
 *   hard error (guards a mis-wired companion from cross-contaminating suites).
 */
export async function loadCompanionMap(file, expectedSuite) {
  const quads = [...(await parseRdf(readFileSync(file, "utf8"), "text/turtle", {}))];

  // subject -> { id, testCases:Set<IRI> }
  const bySubject = new Map();
  const ensure = (s) => {
    let v = bySubject.get(s);
    if (!v) bySubject.set(s, (v = { id: null, testCases: new Set() }));
    return v;
  };

  let companionOf = null;
  let specVersion = null;
  for (const q of quads) {
    const p = q.predicate.value;
    if (p === DCT + "identifier") ensure(q.subject.value).id = q.object.value;
    else if (p === SPEC + "testCase") ensure(q.subject.value).testCases.add(q.object.value);
    else if (p === SC + "companionOf") companionOf = q.object.value;
    else if (p === SC + "specVersion") specVersion = q.object.value;
  }

  const caseToStatements = new Map();
  const statementToCases = new Map();
  const statementIds = new Set();

  for (const { id, testCases } of bySubject.values()) {
    if (!id) continue;
    if (!STATEMENT_ID_RE.test(id)) throw new Error(`${file}: bad statement id "${id}"`);
    statementIds.add(id);
    for (const tc of testCases) {
      // .../vectors/<suite>/cases/<slug>[/]
      const m = tc.match(/\/vectors\/([^/]+)\/cases\/([^/]+)\/?$/);
      if (!m) throw new Error(`${file}: unparseable spec:testCase IRI "${tc}" (statement ${id})`);
      const [, suite, slug] = m;
      if (suite !== expectedSuite) {
        throw new Error(
          `${file}: statement ${id} pins case in suite "${suite}", expected "${expectedSuite}"`,
        );
      }
      if (!caseToStatements.has(slug)) caseToStatements.set(slug, new Set());
      caseToStatements.get(slug).add(id);
      if (!statementToCases.has(id)) statementToCases.set(id, new Set());
      statementToCases.get(id).add(slug);
    }
  }

  return { companionOf, specVersion, caseToStatements, statementToCases, statementIds };
}

/**
 * The suite -> companion binding for the migration. Companion files live in each
 * spec's OWN repo (jeswr/spec-companion DESIGN §6); by default we read the sibling
 * checkouts under the shared repo root, overridable with $SPEC_COMPANION_ROOT.
 * A suite absent here (e.g. odrl-delegation, whose spec has no companion yet) is
 * intentionally NOT migrated — its cases keep `clauses` only.
 */
export const SUITE_COMPANIONS = {
  "a2a-rdf": { repo: "jeswr/a2a-rdf-extension", dir: "a2a-rdf-extension" },
  "agent-authz-credential": {
    repo: "jeswr/agent-authz-credential-spec",
    dir: "agent-authz-credential-spec",
  },
};
