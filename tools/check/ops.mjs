// AUTHORED-BY Claude Fable 5
//
// The abstract-operation registry (README §Abstract operations), implemented
// against the PINNED reference implementations. Each entry receives
// (input, caseDir) — file-referenced inputs resolve relative to caseDir — and
// returns a JSON value compared verbatim against the case's `expected`.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { evaluateDelegated, parsePolicy } from "@jeswr/solid-odrl";

/** Read a case-relative document. */
export function doc(caseDir, name) {
  return readFileSync(join(caseDir, name), "utf8");
}

export const ops = {
  /** ODRL Agent-Delegation Profile §5–§7 — the fail-closed chain evaluation. */
  "evaluate-delegated-chain": async (input, caseDir) => {
    const chain = [];
    for (const ref of input.chain) {
      const policy = await parsePolicy(doc(caseDir, ref));
      if (policy === undefined) throw new Error(`${ref}: no policy parsed`);
      chain.push(policy);
    }
    const result = evaluateDelegated(chain, input.request, {
      now: new Date(input.now),
      revoked: input.revoked,
    });
    return { decision: result.decision };
  },
};
