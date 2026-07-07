// AUTHORED-BY Claude Fable 5
//
// The stable spec-companion statement-id pattern (jeswr/spec-companion: upper
// alphanumeric + hyphen, e.g. AAC-VER-1, A2ARDF-DG-1). Kept in a zero-dependency
// leaf module so the base-gate checker (check/statement-ids.mjs) can validate the
// committed vectors without importing the RDF parser.

export const STATEMENT_ID_RE = /^[A-Z0-9][A-Z0-9-]*$/;
