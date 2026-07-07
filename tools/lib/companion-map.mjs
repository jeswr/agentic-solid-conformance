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
import { SUITE_COMPANIONS } from "./companions.mjs";

const SPEC = "http://www.w3.org/ns/spec#";
const DCT = "http://purl.org/dc/terms/";
const SC = "https://w3id.org/jeswr/spec-companion#";

export { STATEMENT_ID_RE, SUITE_COMPANIONS };

/**
 * Parse an already-loaded companion Turtle STRING (the testable core of
 * loadCompanionMap). Returns:
 *   { companionOf, specVersion,
 *     caseToStatements: Map<caseSlug, Set<statementId>>,
 *     statementToCases: Map<statementId, Set<caseSlug>>,
 *     statementIds: Set<statementId> }
 *
 * Fidelity guards (the migration derives an EXACT inverse of `spec:testCase`, so
 * anything that would silently drop a link is a hard error):
 *   • required provenance — `sc:companionOf` and `sc:specVersion` MUST be present
 *     (the generator records them, and a companion without them is malformed);
 *   • a subject carrying `spec:testCase` links MUST also carry a `dcterms:identifier`
 *     — otherwise its test-case links would be silently ignored and the inverse map
 *     would miss them;
 *   • statement ids match the id pattern; every `spec:testCase` IRI resolves to a
 *     case under `expectedSuite` (a foreign suite is a mis-wired companion).
 *
 * @param {string} ttl  the companion Turtle text
 * @param {string} expectedSuite  the vector suite the companion's cases live under
 * @param {string} source  a label for error messages (the file path, usually)
 */
export async function parseCompanionTtl(ttl, expectedSuite, source = "<companion>") {
  const quads = [...(await parseRdf(ttl, "text/turtle", {}))];

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

  if (!companionOf) throw new Error(`${source}: companion has no sc:companionOf`);
  if (!specVersion) throw new Error(`${source}: companion has no sc:specVersion`);

  const caseToStatements = new Map();
  const statementToCases = new Map();
  const statementIds = new Set();

  for (const [subject, { id, testCases }] of bySubject) {
    if (!id) {
      // A subject with spec:testCase links but no stable id would be silently
      // dropped — that breaks the exact-inverse fidelity the migration relies on.
      if (testCases.size > 0) {
        throw new Error(
          `${source}: subject <${subject}> has ${testCases.size} spec:testCase link(s) but no dcterms:identifier`,
        );
      }
      continue;
    }
    if (!STATEMENT_ID_RE.test(id)) throw new Error(`${source}: bad statement id "${id}"`);
    statementIds.add(id);
    for (const tc of testCases) {
      // .../vectors/<suite>/cases/<slug>[/]
      const m = tc.match(/\/vectors\/([^/]+)\/cases\/([^/]+)\/?$/);
      if (!m) throw new Error(`${source}: unparseable spec:testCase IRI "${tc}" (statement ${id})`);
      const [, suite, slug] = m;
      if (suite !== expectedSuite) {
        throw new Error(
          `${source}: statement ${id} pins case in suite "${suite}", expected "${expectedSuite}"`,
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
 * Parse a companion `spec.statements.ttl` file. Thin wrapper over
 * {@link parseCompanionTtl} that reads the file first.
 *
 * @param {string} file  path to the companion `spec.statements.ttl`
 * @param {string} expectedSuite  the vector suite the companion's cases live under
 */
export async function loadCompanionMap(file, expectedSuite) {
  return parseCompanionTtl(readFileSync(file, "utf8"), expectedSuite, file);
}
