// AUTHORED-BY Claude Fable 5
//
// Shared fixture-emission helpers for the vector generators: case-directory
// writing, manifest assembly (with the clause → case-id traceability index),
// and stable JSON serialization (sorted keys, 2-space indent, trailing LF) so
// regenerated fixtures diff minimally.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The repo root (tools/ is one level down). */
export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Stable-stringify: objects with sorted keys, arrays in order. */
export function stableJson(value) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v !== null && typeof v === "object") {
      return Object.fromEntries(
        Object.keys(v)
          .sort()
          .map((k) => [k, sort(v[k])]),
      );
    }
    return v;
  };
  return `${JSON.stringify(sort(value), null, 2)}\n`;
}

/** Write a file, creating parent dirs. Text gets a guaranteed trailing LF. */
export function writeFixture(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  const text = typeof content === "string" ? content : stableJson(content);
  writeFileSync(path, text.endsWith("\n") ? text : `${text}\n`, "utf8");
}

/**
 * A suite builder: collects cases (each already written to its dir by the
 * caller) and emits vectors/<suite>/manifest.json with the clause index.
 */
export class SuiteManifest {
  constructor({ suite, spec, description }) {
    this.suite = suite;
    this.spec = spec;
    this.description = description;
    this.cases = [];
  }

  /** Record a case (path relative to the suite dir) with its clause pins. */
  add(caseJson, relPath) {
    this.cases.push({ id: caseJson.id, path: relPath, clauses: caseJson.clauses });
  }

  write() {
    const clauseIndex = {};
    for (const c of this.cases) {
      for (const clause of c.clauses) {
        (clauseIndex[clause] ??= []).push(c.id);
      }
    }
    writeFixture(join(REPO_ROOT, "vectors", this.suite, "manifest.json"), {
      suite: this.suite,
      spec: this.spec,
      description: this.description,
      schemaVersion: 1,
      caseCount: this.cases.length,
      cases: this.cases.map((c) => ({ id: c.id, path: c.path })),
      clauseIndex,
    });
  }
}

/** Write one case dir: case.json + any referenced documents. */
export function writeCase(suite, caseId, caseJson, documents = {}) {
  const dir = join(REPO_ROOT, "vectors", suite, "cases", caseId);
  for (const [name, body] of Object.entries(documents)) {
    writeFixture(join(dir, name), body);
  }
  writeFixture(join(dir, "case.json"), caseJson);
  return `cases/${caseId}/case.json`;
}
