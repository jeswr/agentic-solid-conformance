// AUTHORED-BY Claude Fable 5
//
// SELF-CONTAINED consistency check for the companion statement-id migration
// (case.json.statements + manifest.statementIndex + manifest.statementCompanion).
// Needs NO companion and NO reference implementation — it validates that the
// committed vectors are internally coherent, so it runs on a clean checkout and
// in the base gate. Regenerating the ids against the source companions is the job
// of generate/statement-ids.mjs; this only checks what was committed.
//
// Invariants enforced per suite that carries a statementIndex:
//   1. statementCompanion provenance present (companion IRI + specVersion + repo).
//   2. every statement id (index keys + case `statements`) matches the id pattern.
//   3. bidirectional: statementIndex[id] lists exactly the cases whose
//      `statements` include id, and vice-versa — no dangling either way.
//   4. no empty `statements` array (a case is either pinned or has no field).
//   5. every case id referenced by the index resolves to a real manifest case.
// A suite WITHOUT a statementIndex (e.g. odrl-delegation — no companion yet) is
// skipped, not failed: the migration is opt-in per landed companion.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "../lib/emit.mjs";
import { STATEMENT_ID_RE } from "../lib/statement-id.mjs";

const suites = ["a2a-rdf", "agent-authz-credential", "odrl-delegation"];
const problems = [];
let checkedSuites = 0;

for (const suite of suites) {
  const manifestPath = join(REPO_ROOT, "vectors", suite, "manifest.json");
  if (!existsSync(manifestPath)) continue;
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (!manifest.statementIndex) continue; // un-migrated suite
  checkedSuites++;
  const fail = (m) => problems.push(`${suite}: ${m}`);

  // (1) provenance
  const prov = manifest.statementCompanion;
  if (!prov || !prov.companion || !prov.specVersion || !prov.repo) {
    fail("statementIndex present but statementCompanion provenance is incomplete");
  }

  const validCaseIds = new Set(manifest.cases.map((c) => c.id));

  // (2)+(5) index shape
  for (const [id, caseIds] of Object.entries(manifest.statementIndex)) {
    if (!STATEMENT_ID_RE.test(id)) fail(`statementIndex key "${id}" is not a valid statement id`);
    if (!Array.isArray(caseIds) || caseIds.length === 0) {
      fail(`statementIndex["${id}"] must be a non-empty array`);
      continue;
    }
    for (const cid of caseIds) {
      if (!validCaseIds.has(cid)) fail(`statementIndex["${id}"] references unknown case "${cid}"`);
    }
    const sorted = [...caseIds].slice().sort();
    if (JSON.stringify(sorted) !== JSON.stringify(caseIds)) {
      fail(`statementIndex["${id}"] is not sorted`);
    }
  }

  // Rebuild the index from the cases and compare to the manifest (invariant 3+4).
  const rebuilt = {};
  for (const entry of manifest.cases) {
    const c = JSON.parse(readFileSync(join(REPO_ROOT, "vectors", suite, entry.path), "utf8"));
    if (!("statements" in c)) continue;
    const s = c.statements;
    if (!Array.isArray(s) || s.length === 0) {
      fail(`case ${c.id} has an empty/invalid \`statements\` array (omit the field instead)`);
      continue;
    }
    const sorted = [...s].slice().sort();
    if (JSON.stringify(sorted) !== JSON.stringify(s)) fail(`case ${c.id} \`statements\` not sorted`);
    for (const id of s) {
      if (!STATEMENT_ID_RE.test(id)) fail(`case ${c.id} bad statement id "${id}"`);
      (rebuilt[id] ??= []).push(c.id);
    }
  }
  for (const id of Object.keys(rebuilt)) rebuilt[id].sort();

  const idxKeys = Object.keys(manifest.statementIndex).sort();
  const rebKeys = Object.keys(rebuilt).sort();
  if (JSON.stringify(idxKeys) !== JSON.stringify(rebKeys)) {
    fail(
      `statementIndex keys {${idxKeys}} != ids pinned by cases {${rebKeys}} (bidirectional mismatch)`,
    );
  } else {
    for (const id of idxKeys) {
      if (JSON.stringify(manifest.statementIndex[id]) !== JSON.stringify(rebuilt[id])) {
        fail(
          `statementIndex["${id}"] {${manifest.statementIndex[id]}} != cases pinning it {${rebuilt[id]}}`,
        );
      }
    }
  }
}

if (problems.length > 0) {
  console.error(`statement-ids: ${problems.length} problem(s):`);
  for (const p of problems) console.error(`  FAIL ${p}`);
  process.exit(1);
}
console.log(`statement-ids: OK (${checkedSuites} migrated suite(s) internally consistent)`);
