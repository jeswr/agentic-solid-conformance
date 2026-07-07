// AUTHORED-BY Claude Fable 5
//
// Regression tests for the two roborev findings on the companion statement-id
// migration:
//   (1) MEDIUM — a companion-backed suite whose statementIndex was DELETED must
//       FAIL the base gate (it was silently skipped before).
//   (2) LOW — a companion subject with spec:testCase links but NO dcterms:identifier
//       must THROW (silently ignoring it broke exact-inverse fidelity).
// Plus happy-path + adjacent guards. Run with `node --test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { checkStatementIds } from "../check/statement-ids.mjs";
import { parseCompanionTtl } from "../lib/companion-map.mjs";

const TTL_HEAD = `@base <https://example.org/spec.statements.ttl> .
@prefix sc:      <https://w3id.org/jeswr/spec-companion#> .
@prefix spec:    <http://www.w3.org/ns/spec#> .
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix vec:     <https://github.com/jeswr/agentic-solid-conformance/tree/main/vectors/a2a-rdf/cases/> .
`;
const DOC = `<> a sc:CompanionDocument ; sc:companionOf <https://example.org/> ; sc:specVersion "abc1234" .\n`;

// --- Finding (1): gutted manifest -> checker FAILS ------------------------------

test("companion-backed suite missing statementIndex FAILS (finding 1)", () => {
  const suites = [
    {
      name: "a2a-rdf",
      manifest: { suite: "a2a-rdf", cases: [{ id: "a2a-rdf/x", path: "cases/x/case.json" }] },
      cases: { "a2a-rdf/x": { id: "a2a-rdf/x", clauses: ["§X"] } },
    },
  ];
  const { problems } = checkStatementIds(suites);
  assert.equal(problems.length, 1, `expected exactly one problem, got: ${problems.join(" | ")}`);
  assert.match(problems[0], /a2a-rdf: companion-backed suite is missing statementIndex/);
});

test("deleting the whole manifest of a companion-backed suite FAILS", () => {
  const { problems } = checkStatementIds([
    { name: "agent-authz-credential", manifest: null, cases: {} },
  ]);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /agent-authz-credential: companion-backed suite has no manifest/);
});

test("a declared no-companion suite without statementIndex is allowed (skipped)", () => {
  const { problems, checked } = checkStatementIds([
    {
      name: "odrl-delegation",
      manifest: { suite: "odrl-delegation", cases: [{ id: "odrl-delegation/a" }] },
      cases: { "odrl-delegation/a": { id: "odrl-delegation/a", clauses: ["§1"] } },
    },
  ]);
  assert.deepEqual(problems, []);
  assert.equal(checked, 0);
});

test("an UNDECLARED suite without statementIndex FAILS fail-closed", () => {
  const { problems } = checkStatementIds([
    { name: "brand-new-suite", manifest: { suite: "brand-new-suite", cases: [] }, cases: {} },
  ]);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /not declared companion-backed or no-companion/);
});

test("a well-formed migrated suite PASSES", () => {
  const suites = [
    {
      name: "a2a-rdf",
      manifest: {
        suite: "a2a-rdf",
        cases: [
          { id: "a2a-rdf/a", path: "cases/a/case.json" },
          { id: "a2a-rdf/b", path: "cases/b/case.json" },
        ],
        statementIndex: { "A2ARDF-1": ["a2a-rdf/a", "a2a-rdf/b"], "A2ARDF-2": ["a2a-rdf/b"] },
        statementCompanion: { companion: "https://x/", repo: "jeswr/a2a-rdf-extension", specVersion: "d3a2773" },
      },
      cases: {
        "a2a-rdf/a": { id: "a2a-rdf/a", statements: ["A2ARDF-1"] },
        "a2a-rdf/b": { id: "a2a-rdf/b", statements: ["A2ARDF-1", "A2ARDF-2"] },
      },
    },
  ];
  const { problems, checked } = checkStatementIds(suites);
  assert.deepEqual(problems, [], problems.join(" | "));
  assert.equal(checked, 1);
});

test("a bidirectional mismatch (case pins an id the index omits) FAILS", () => {
  const suites = [
    {
      name: "a2a-rdf",
      manifest: {
        suite: "a2a-rdf",
        cases: [{ id: "a2a-rdf/a", path: "cases/a/case.json" }],
        statementIndex: { "A2ARDF-1": ["a2a-rdf/a"] },
        statementCompanion: { companion: "https://x/", repo: "jeswr/a2a-rdf-extension", specVersion: "d3a2773" },
      },
      cases: { "a2a-rdf/a": { id: "a2a-rdf/a", statements: ["A2ARDF-1", "A2ARDF-9"] } },
    },
  ];
  const { problems } = checkStatementIds(suites);
  assert.ok(problems.some((p) => /bidirectional mismatch/.test(p)), problems.join(" | "));
});

test("statementIndex present but provenance incomplete FAILS", () => {
  const suites = [
    {
      name: "a2a-rdf",
      manifest: {
        suite: "a2a-rdf",
        cases: [{ id: "a2a-rdf/a" }],
        statementIndex: { "A2ARDF-1": ["a2a-rdf/a"] },
        // statementCompanion missing
      },
      cases: { "a2a-rdf/a": { id: "a2a-rdf/a", statements: ["A2ARDF-1"] } },
    },
  ];
  const { problems } = checkStatementIds(suites);
  assert.ok(problems.some((p) => /statementCompanion provenance is incomplete/.test(p)));
});

// --- Finding (2): id-less companion subject with testCases -> THROWS -------------

test("companion subject with spec:testCase but no identifier THROWS (finding 2)", async () => {
  const ttl = TTL_HEAD + DOC + `<#NOID> a spec:Requirement ; spec:testCase vec:some-case .\n`;
  await assert.rejects(
    () => parseCompanionTtl(ttl, "a2a-rdf", "fixture"),
    /has 1 spec:testCase link\(s\) but no dcterms:identifier/,
  );
});

test("a well-formed companion parses to the exact inverse", async () => {
  const ttl =
    TTL_HEAD +
    DOC +
    `<#S1> a spec:Requirement ; dcterms:identifier "X-1" ; spec:testCase vec:case-a , vec:case-b .\n` +
    `<#S2> a spec:Requirement ; dcterms:identifier "X-2" ; spec:testCase vec:case-b .\n`;
  const { companionOf, specVersion, caseToStatements } = await parseCompanionTtl(ttl, "a2a-rdf", "fixture");
  assert.equal(companionOf, "https://example.org/");
  assert.equal(specVersion, "abc1234");
  assert.deepEqual([...caseToStatements.get("case-a")].sort(), ["X-1"]);
  assert.deepEqual([...caseToStatements.get("case-b")].sort(), ["X-1", "X-2"]);
});

test("a companion missing sc:companionOf THROWS", async () => {
  const ttl = TTL_HEAD + `<> a sc:CompanionDocument ; sc:specVersion "abc1234" .\n<#S1> a spec:Requirement ; dcterms:identifier "X-1" .\n`;
  await assert.rejects(() => parseCompanionTtl(ttl, "a2a-rdf", "fixture"), /no sc:companionOf/);
});

test("a companion missing sc:specVersion THROWS", async () => {
  const ttl = TTL_HEAD + `<> a sc:CompanionDocument ; sc:companionOf <https://example.org/> .\n<#S1> a spec:Requirement ; dcterms:identifier "X-1" .\n`;
  await assert.rejects(() => parseCompanionTtl(ttl, "a2a-rdf", "fixture"), /no sc:specVersion/);
});

test("a companion pinning a foreign suite THROWS", async () => {
  const ttl = TTL_HEAD + DOC + `<#S1> a spec:Requirement ; dcterms:identifier "X-1" ; spec:testCase vec:case-a .\n`;
  await assert.rejects(
    () => parseCompanionTtl(ttl, "agent-authz-credential", "fixture"),
    /pins case in suite "a2a-rdf", expected "agent-authz-credential"/,
  );
});
