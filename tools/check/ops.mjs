// AUTHORED-BY Claude Fable 5
//
// The abstract-operation registry (README §Abstract operations), implemented
// against the PINNED reference implementations. Each entry receives
// (input, caseDir) — file-referenced inputs resolve relative to caseDir — and
// returns a JSON value compared verbatim against the case's `expected`.

import { subtle } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { verifyAgentAuthority } from "@jeswr/accountable-agent-runtime";
import { evaluateDelegated, parsePolicy } from "@jeswr/solid-odrl";
import { REPO_ROOT } from "../lib/emit.mjs";

/** Read a case-relative document. */
export function doc(caseDir, name) {
  return readFileSync(join(caseDir, name), "utf8");
}

// --- the agent-authz keyring (suite-level controller documents) --------------
// Loaded lazily; resolves verificationMethod → public CryptoKey, and implements
// the AAC #sec-issuer-binding controller check from the SHIPPED documents alone:
// a verification method is controlled by an issuer iff a controller document
// whose id IS that issuer lists it under assertionMethod.
let keyringPromise;
async function loadKeyring() {
  keyringPromise ??= (async () => {
    const dir = join(REPO_ROOT, "vectors", "agent-authz-credential", "keyring");
    const byVm = new Map(); // vm → { key, controller }
    for (const file of readdirSync(dir)) {
      const cd = JSON.parse(readFileSync(join(dir, file), "utf8"));
      const assertion = new Set(cd.assertionMethod ?? []);
      for (const vm of cd.verificationMethod ?? []) {
        if (!assertion.has(vm.id)) continue; // only assertion-capable keys resolve
        const key = await subtle.importKey("jwk", vm.publicKeyJwk, { name: "Ed25519" }, false, [
          "verify",
        ]);
        byVm.set(vm.id, { key, controller: cd.id });
      }
    }
    return {
      resolveKey: (vm) => byVm.get(vm)?.key,
      isControlledBy: (vm, issuer) => byVm.get(vm)?.controller === issuer,
    };
  })();
  return keyringPromise;
}

/** Materialize a {credentials, policies} chain reference from case-dir files. */
async function loadChain(caseDir, ref) {
  const credentials = ref.credentials.map((f) => JSON.parse(doc(caseDir, f)));
  const policies = [];
  for (const f of ref.policies) {
    const p = await parsePolicy(doc(caseDir, f));
    if (p === undefined) throw new Error(`${f}: no policy parsed`);
    policies.push(p);
  }
  return { credentials, policies };
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

  /** AAC #verification — the four-phase chain verification (+ identity composition). */
  "verify-agent-authority": async (input, caseDir) => {
    const keyring = await loadKeyring();
    const primary = await loadChain(caseDir, input.primaryChain);
    const actorChain =
      input.actorChain !== undefined ? await loadChain(caseDir, input.actorChain) : undefined;
    const r = await verifyAgentAuthority(primary, {
      request: input.request,
      rootPrincipal: input.rootPrincipal,
      now: new Date(input.now),
      resolveKey: keyring.resolveKey,
      isControlledBy: keyring.isControlledBy,
      revoked: input.revoked,
      ...(input.statusUnreachable !== undefined && {
        statusUnreachable: input.statusUnreachable,
      }),
      ...(input.maxChainLength !== undefined && { maxChainLength: input.maxChainLength }),
      ...(input.actor !== undefined && { actor: input.actor }),
      ...(actorChain !== undefined && { actorChain }),
    });
    return { authorized: r.authorized, phase: r.phase, ...(r.code && { code: r.code }) };
  },
};
