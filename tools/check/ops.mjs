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
import { parseRdf } from "@jeswr/fetch-rdf";
import {
  canonicalNQuads,
  decodeUpgradeOffer,
  decodeUpgradeResponse,
  hashQuads,
  mayDowngradeToNl,
  validateIntent,
  verifyProtocolDocument,
} from "@jeswr/solid-a2a";
import { resolveBoundPolicy, verifyCredential, verifyPresentation } from "@jeswr/solid-vc";

/** Parse a Turtle document to quads. */
async function quadsOf(caseDir, name) {
  return [...(await parseRdf(doc(caseDir, name), "text/turtle", {}))];
}

const ODRLD_REVOKED_POLICY = "https://w3id.org/jeswr/odrl-delegation#revokedPolicy";

/**
 * The effective revoked set: the case's literal `revoked` IRIs UNIONED with the
 * `odrld:revokedPolicy` objects of every shipped `odrld:Revocation` document
 * (`revocationDocuments`) — so the vectors exercise revocation-STATEMENT parsing,
 * not just a pre-derived array (ODRL-delegation §4.3/§7; AAC
 * #revocation-verification rule 2).
 */
async function effectiveRevoked(input, caseDir) {
  const revoked = new Set(input.revoked ?? []);
  for (const ref of input.revocationDocuments ?? []) {
    for (const quad of await quadsOf(caseDir, ref)) {
      if (quad.predicate.value === ODRLD_REVOKED_POLICY && quad.object.termType === "NamedNode") {
        revoked.add(quad.object.value);
      }
    }
  }
  return [...revoked];
}
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
      revoked: await effectiveRevoked(input, caseDir),
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
      revoked: await effectiveRevoked(input, caseDir),
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

  /** AAC #policy-binding / #verification step 1 — policy-content binding. */
  "resolve-bound-policy": async (input, caseDir) => {
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
      const octets = new TextEncoder().encode(body);
      return {
        ok: true,
        status: 200,
        headers: { get: (n) => (n.toLowerCase() === "content-type" ? "text/turtle" : null) },
        text: async () => body,
        arrayBuffer: async () => octets.buffer,
      };
    };
    const r = await resolveBoundPolicy(credential, {
      ...(Object.keys(input.documents).length > 0 && { fetch: fetchPort }),
    });
    return {
      ok: r.errors.length === 0,
      ...(r.policy?.form !== undefined && { form: r.policy.form }),
      codes: r.errors.map((e) => e.code),
    };
  },

  /** A2A RDF extension §Content addressing — RDFC-1.0 canonical N-Quads → sha256. */
  "rdfc10-hash": async (input, caseDir) => {
    const quads = await quadsOf(caseDir, input.graph);
    const hash = await hashQuads(quads);
    const canonical = await canonicalNQuads(quads);
    // `expected.canonical` is a FILE REFERENCE: compare byte-exactly, then echo the
    // reference so deepEqual against `expected` closes over both fields.
    const want = doc(caseDir, "canonical.nq");
    return { hash, canonical: canonical === want ? "canonical.nq" : "<canonicalization drift>" };
  },

  /** A2A RDF extension §Content addressing — reject a body that misses its pin. */
  "verify-pd-pin": async (input, caseDir) => {
    return { ok: await verifyProtocolDocument(doc(caseDir, input.body), input.pinnedHash) };
  },

  /** A2A RDF extension §Upgrade offer / §Upgrade response — strict payload decode. */
  "decode-handshake": async (input) => {
    try {
      const p = input.payload;
      if (p?.kind === "upgrade-offer") decodeUpgradeOffer(p);
      else decodeUpgradeResponse(p);
      return { ok: true };
    } catch {
      return { ok: false };
    }
  },

  /** A2A RDF extension §The no-silent-downgrade rule. */
  "may-downgrade-to-nl": async (input) => {
    return {
      downgrade: mayDowngradeToNl(
        decodeUpgradeOffer(input.offer),
        decodeUpgradeResponse(input.response),
      ),
    };
  },

  /** A2A RDF extension §Message-content binding — mandatory pre-action SHACL validation. */
  "validate-intent": async (input, caseDir) => {
    const report = await validateIntent(
      await quadsOf(caseDir, input.dataGraph),
      await quadsOf(caseDir, input.shapesGraph),
    );
    return { conforms: report.conforms };
  },
};
