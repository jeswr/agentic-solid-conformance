// AUTHORED-BY Claude Fable 5
//
// SELF-CONTAINED consistency check for the companion statement-id migration
// (case.json.statements + manifest.statementIndex + manifest.statementCompanion).
// Needs NO companion and NO reference implementation — it validates that the
// committed vectors are internally coherent, so it runs on a clean checkout and in
// the base gate. Regenerating the ids against the source companions is the job of
// generate/statement-ids.mjs; this only checks what was committed.
//
// The core is the pure `checkStatementIds(suites)` (unit-tested); the CLI at the
// bottom reads the vectors from disk and feeds it.
//
// Per-suite policy (fail-CLOSED so migration metadata can never be dropped silently):
//   • a COMPANION-BACKED suite (lib/companions.SUITE_COMPANIONS) MUST carry
//     statementIndex + statementCompanion — deleting them is a gate FAILURE, not a
//     skip;
//   • a suite explicitly declared to have NO companion (NO_COMPANION_SUITES) may
//     legitimately carry no statement metadata — skipped;
//   • any other suite lacking statement metadata is an ERROR (declare it in one of
//     the two lists, or migrate it).
//
// Per suite that DOES carry a statementIndex, the invariants:
//   1. statementCompanion provenance present (companion IRI + specVersion + repo).
//   2. every statement id (index keys + case `statements`) matches the id pattern.
//   3. bidirectional: statementIndex[id] lists exactly the cases whose `statements`
//      include id, and vice-versa — no dangling either way.
//   4. no empty `statements` array (a case is either pinned or has no field).
//   5. every case id referenced by the index resolves to a real manifest case.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { REPO_ROOT } from "../lib/emit.mjs";
import { STATEMENT_ID_RE } from "../lib/statement-id.mjs";
import { NO_COMPANION_SUITES, SUITE_COMPANIONS } from "../lib/companions.mjs";

const COMPANION_BACKED = new Set(Object.keys(SUITE_COMPANIONS));
const NO_COMPANION = new Set(NO_COMPANION_SUITES);

const jsonEq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * Pure consistency check.
 * @param {Array<{name:string, manifest:object|null, cases:Record<string,object>}>} suites
 *   `manifest` is null when the suite has no manifest.json; `cases` maps each
 *   case id to its parsed case.json.
 * @returns {{problems:string[], checked:number}}
 */
export function checkStatementIds(suites) {
  const problems = [];
  let checked = 0;

  for (const { name, manifest, cases } of suites) {
    const fail = (m) => problems.push(`${name}: ${m}`);
    const required = COMPANION_BACKED.has(name);

    if (!manifest) {
      if (required) fail("companion-backed suite has no manifest.json");
      continue;
    }

    if (!manifest.statementIndex) {
      if (required) {
        fail(
          "companion-backed suite is missing statementIndex — migration metadata deleted? (must carry statementIndex + statementCompanion)",
        );
      } else if (!NO_COMPANION.has(name)) {
        fail(
          "no statementIndex and the suite is not declared companion-backed or no-companion — declare it in lib/companions.mjs or migrate it",
        );
      }
      continue; // no index to validate further
    }

    // Has an index → validate it fully (required suites additionally need provenance).
    checked++;
    const prov = manifest.statementCompanion;
    if (!prov || !prov.companion || !prov.specVersion || !prov.repo) {
      fail("statementIndex present but statementCompanion provenance is incomplete");
    }

    const validCaseIds = new Set((manifest.cases ?? []).map((c) => c.id));

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
      if (!jsonEq([...caseIds].sort(), caseIds)) fail(`statementIndex["${id}"] is not sorted`);
    }

    // Rebuild the index from the cases and compare (invariants 3+4).
    const rebuilt = {};
    for (const [cid, c] of Object.entries(cases)) {
      if (!("statements" in c)) continue;
      const s = c.statements;
      if (!Array.isArray(s) || s.length === 0) {
        fail(`case ${cid} has an empty/invalid \`statements\` array (omit the field instead)`);
        continue;
      }
      if (!jsonEq([...s].sort(), s)) fail(`case ${cid} \`statements\` not sorted`);
      for (const id of s) {
        if (!STATEMENT_ID_RE.test(id)) fail(`case ${cid} bad statement id "${id}"`);
        (rebuilt[id] ??= []).push(cid);
      }
    }
    for (const id of Object.keys(rebuilt)) rebuilt[id].sort();

    const idxKeys = Object.keys(manifest.statementIndex).sort();
    const rebKeys = Object.keys(rebuilt).sort();
    if (!jsonEq(idxKeys, rebKeys)) {
      fail(`statementIndex keys {${idxKeys}} != ids pinned by cases {${rebKeys}} (bidirectional mismatch)`);
    } else {
      for (const id of idxKeys) {
        if (!jsonEq(manifest.statementIndex[id], rebuilt[id])) {
          fail(`statementIndex["${id}"] {${manifest.statementIndex[id]}} != cases pinning it {${rebuilt[id]}}`);
        }
      }
    }
  }

  return { problems, checked };
}

/** Load every suite under vectors/ from disk into the checker's input shape. */
export function loadSuitesFromDisk(vectorsDir = join(REPO_ROOT, "vectors")) {
  const suites = [];
  for (const name of readdirSync(vectorsDir).sort()) {
    const suiteDir = join(vectorsDir, name);
    const manifestPath = join(suiteDir, "manifest.json");
    if (!existsSync(manifestPath)) {
      suites.push({ name, manifest: null, cases: {} });
      continue;
    }
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    const cases = {};
    for (const entry of manifest.cases ?? []) {
      cases[entry.id] = JSON.parse(readFileSync(join(suiteDir, entry.path), "utf8"));
    }
    suites.push({ name, manifest, cases });
  }
  return suites;
}

// ---- CLI -----------------------------------------------------------------------
// Run directly (not when imported by a test).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { problems, checked } = checkStatementIds(loadSuitesFromDisk());
  if (problems.length > 0) {
    console.error(`statement-ids: ${problems.length} problem(s):`);
    for (const p of problems) console.error(`  FAIL ${p}`);
    process.exit(1);
  }
  console.log(`statement-ids: OK (${checked} migrated suite(s) internally consistent)`);
}
