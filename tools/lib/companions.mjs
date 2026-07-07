// AUTHORED-BY Claude Fable 5
//
// The suite ↔ spec-companion binding, in a ZERO-DEPENDENCY leaf module so BOTH the
// RDF-reading generator (generate/statement-ids.mjs, via companion-map) and the
// fetch-rdf-free base-gate checker (check/statement-ids.mjs) share ONE source of
// truth for "which vector suites are companion-backed". This is what lets the
// checker REQUIRE the migration metadata on companion-backed suites instead of
// silently skipping a suite whose statementIndex was deleted.

/**
 * Suites whose spec has a landed companion — the migration is REQUIRED here: the
 * manifest MUST carry `statementIndex` + `statementCompanion`. Companion files live
 * in each spec's OWN repo (jeswr/spec-companion DESIGN §6); by default the generator
 * reads the sibling checkouts under the shared repo root ($SPEC_COMPANION_ROOT).
 */
export const SUITE_COMPANIONS = {
  "a2a-rdf": { repo: "jeswr/a2a-rdf-extension", dir: "a2a-rdf-extension" },
  "agent-authz-credential": {
    repo: "jeswr/agent-authz-credential-spec",
    dir: "agent-authz-credential-spec",
  },
};

/**
 * Suites explicitly known to have NO companion yet (their spec has none) — the
 * checker legitimately skips these. A suite that is in NEITHER list and carries no
 * statement metadata is a fail-closed error: it must be declared here or migrated,
 * so migration metadata can never be dropped unnoticed.
 */
export const NO_COMPANION_SUITES = ["odrl-delegation"];
