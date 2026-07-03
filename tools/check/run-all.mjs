// AUTHORED-BY Claude Fable 5
//
// CONSISTENCY CHECKER — the repo's gate. Plays the role of "an implementation
// under test", except the implementation IS the pinned reference stack: it reads
// every vectors/<suite>/manifest.json, resolves each case's file-referenced
// inputs from disk (never from the generators' in-memory objects), dispatches on
// the abstract operation, and compares against `expected`. A vector that drifted
// from the reference implementations fails here.
//
// This file doubles as the executable definition of the README's abstract
// operations: each `ops` entry shows an independent implementer exactly what to
// wire where.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "../lib/emit.mjs";
import { ops } from "./ops.mjs";

const vectorsDir = join(REPO_ROOT, "vectors");
let pass = 0;
let fail = 0;
const failures = [];

/** Deep equality over JSON-shaped values. */
function deepEqual(a, b) {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((v, i) => deepEqual(v, b[i]));
  }
  if (a !== null && b !== null && typeof a === "object" && typeof b === "object") {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return deepEqual(ka, kb) && ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

for (const suite of readdirSync(vectorsDir).sort()) {
  const manifestPath = join(vectorsDir, suite, "manifest.json");
  if (!existsSync(manifestPath)) {
    fail++;
    failures.push(`${suite}: missing manifest.json (empty suite directory)`);
    continue;
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (manifest.caseCount !== manifest.cases.length) {
    fail++;
    failures.push(`${suite}: manifest caseCount ${manifest.caseCount} ≠ ${manifest.cases.length}`);
  }
  for (const entry of manifest.cases) {
    const caseDir = join(vectorsDir, suite, entry.path, "..");
    const c = JSON.parse(readFileSync(join(vectorsDir, suite, entry.path), "utf8"));
    const op = ops[c.operation];
    if (op === undefined) {
      fail++;
      failures.push(`${c.id}: unknown operation ${c.operation}`);
      continue;
    }
    try {
      const actual = await op(c.input, caseDir);
      if (deepEqual(actual, c.expected)) {
        pass++;
      } else {
        fail++;
        failures.push(
          `${c.id}: expected ${JSON.stringify(c.expected)} got ${JSON.stringify(actual)}`,
        );
      }
    } catch (e) {
      fail++;
      failures.push(`${c.id}: threw ${e?.message ?? e}`);
    }
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) {
  for (const f of failures) console.error(`  FAIL ${f}`);
  process.exit(1);
}
