// AUTHORED-BY Claude Fable 5
//
// MIGRATION: enrich each vector case with the stable spec-companion statement ids
// it exercises (jeswr/spec-companion DESIGN §7 — "migrate case.json.clauses from
// brittle '§5.1' strings to statement ids as companions land; additive field,
// keep both during the transition").
//
// ADDITIVE + IDEMPOTENT: for every suite that has a landed companion
// (lib/companion-map.SUITE_COMPANIONS), this writes/refreshes:
//   • case.json.statements   — the sorted statement ids whose companion
//                              `spec:testCase` pins this case (kept alongside the
//                              existing `clauses`; no other field is touched);
//   • manifest.statementIndex — statementId -> [caseId], mirroring `clauseIndex`;
//   • manifest.statementCompanion — provenance: the companion IRI + its
//                              `sc:specVersion` pin + source repo (so a reader
//                              knows exactly which companion revision the ids
//                              were derived from).
// A case a companion does NOT pin gets NO `statements` field (honest — see the
// wrong-root gap noted in DECISIONS.md); suites with no companion are skipped.
//
// Source of truth = the companion `spec.statements.ttl` in each spec's own repo,
// read from the sibling checkouts under the shared repo root (override with
// $SPEC_COMPANION_ROOT). This tool is a maintenance step; the vectors it produces
// are self-describing and never require it at consume/check time.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { REPO_ROOT, writeFixture } from "../lib/emit.mjs";
import { SUITE_COMPANIONS, loadCompanionMap } from "../lib/companion-map.mjs";

const companionRoot = process.env.SPEC_COMPANION_ROOT
  ? resolve(process.env.SPEC_COMPANION_ROOT)
  : resolve(REPO_ROOT, "..");

let touchedCases = 0;
let unpinned = 0;

for (const [suite, binding] of Object.entries(SUITE_COMPANIONS)) {
  const manifestPath = join(REPO_ROOT, "vectors", suite, "manifest.json");
  if (!existsSync(manifestPath)) {
    console.error(`skip ${suite}: no manifest`);
    continue;
  }
  const companionFile = join(companionRoot, binding.dir, "spec.statements.ttl");
  if (!existsSync(companionFile)) {
    throw new Error(
      `${suite}: companion not found at ${companionFile}. Check out ${binding.repo} beside this repo, or set $SPEC_COMPANION_ROOT.`,
    );
  }

  const { companionOf, specVersion, caseToStatements, statementToCases } =
    await loadCompanionMap(companionFile, suite);

  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const statementIndex = {};

  for (const entry of manifest.cases) {
    const casePath = join(REPO_ROOT, "vectors", suite, entry.path);
    const c = JSON.parse(readFileSync(casePath, "utf8"));
    const slug = c.id.slice(suite.length + 1); // "<suite>/<slug>" -> "<slug>"
    const ids = [...(caseToStatements.get(slug) ?? [])].sort();

    if (ids.length > 0) {
      c.statements = ids;
      for (const id of ids) (statementIndex[id] ??= []).push(c.id);
    } else {
      // Companion does not pin this case: keep `clauses` only, drop any stale
      // `statements` so the field never lies about coverage.
      delete c.statements;
      unpinned++;
    }
    writeFixture(join(dirname(casePath), "case.json"), c);
    touchedCases++;
  }

  // Sanity: the statementIndex we built from the cases must be the exact inverse
  // of the companion's per-statement `spec:testCase` sets (bidirectional).
  for (const [id, slugs] of statementToCases) {
    const fromCases = new Set((statementIndex[id] ?? []).map((cid) => cid.slice(suite.length + 1)));
    const fromCompanion = new Set(slugs);
    const symmetric =
      fromCases.size === fromCompanion.size && [...fromCompanion].every((s) => fromCases.has(s));
    if (!symmetric) {
      throw new Error(
        `${suite}: statement ${id} companion cases {${[...fromCompanion].sort()}} != vector cases {${[...fromCases].sort()}}`,
      );
    }
  }

  for (const id of Object.keys(statementIndex)) statementIndex[id].sort();
  manifest.statementIndex = statementIndex;
  manifest.statementCompanion = {
    companion: companionOf,
    repo: binding.repo,
    specVersion,
    source: `${binding.repo}/spec.statements.ttl`,
    note: "statement ids derived from the companion's spec:testCase links; the case-level `statements` field is additive to `clauses` during the transition (jeswr/spec-companion DESIGN §7).",
  };
  writeFixture(manifestPath, manifest);

  const pinned = Object.keys(statementIndex).length;
  console.log(
    `${suite}: ${manifest.cases.length} cases, ${pinned} statements pinned (companion ${binding.repo}@${specVersion.slice(0, 7)})`,
  );
}

console.log(
  `\nstatement-ids: wrote ${touchedCases} case(s); ${unpinned} case(s) left unpinned (no companion link).`,
);
