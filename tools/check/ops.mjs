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
import { verifyCredential, verifyPresentation } from "@jeswr/solid-vc";
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

  /** AAC #revocation-verification (Bitstring direction) + #sec-status-availability. */
  "verify-credential-status": async (input, caseDir) => {
    const keyring = await loadKeyring();
    const credential = JSON.parse(doc(caseDir, input.credential));
    const fetchPort = async (url) => {
      const entry = input.documents[url];
      if (entry === undefined || typeof entry === "object") {
        const status = typeof entry === "object" ? entry.status : 404;
        return {
          ok: false,
          status,
          headers: { get: () => null },
          text: async () => "",
          arrayBuffer: async () => new ArrayBuffer(0),
        };
      }
      const body = doc(caseDir, entry);
      return {
        ok: true,
        status: 200,
        headers: { get: (n) => (n.toLowerCase() === "content-type" ? "text/turtle" : null) },
        text: async () => body,
        arrayBuffer: async () => new TextEncoder().encode(body).buffer,
      };
    };
    const r = await verifyCredential(credential, {
      resolveKey: keyring.resolveKey,
      isControlledBy: keyring.isControlledBy,
      now: new Date(input.now),
      fetch: fetchPort,
    });
    return { verified: r.verified, codes: r.errors.map((e) => e.code) };
  },

  /** AAC #presentations / #sec-replay — challenge/domain anti-replay binding. */
  "verify-presentation-replay": async (input, caseDir) => {
    const keyring = await loadKeyring();
    const vp = JSON.parse(doc(caseDir, input.presentation));
    const r = await verifyPresentation(vp, {
      resolveKey: keyring.resolveKey,
      isControlledBy: keyring.isControlledBy,
      now: new Date(input.now),
      challenge: input.challenge,
      domain: input.domain,
    });
    return { verified: r.verified, codes: r.errors.map((e) => e.code) };
  },
};
