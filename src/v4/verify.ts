/**
 * @lexitsp/sdk v4 · verify — EXPERIMENTAL
 *
 * Local-only verifier for TSP/4.0-draft envelopes. Mirrors v3's
 * verifyLocal but operates on the v4 envelope shape. Reuses v3's
 * canonical-JSON, SHA-256 and Ed25519 primitives unchanged.
 *
 * Version dispatch: `verifyAny()` looks at `envelope.tsp` and routes
 * v3 envelopes to v3's verifier and v4-draft envelopes to v4's. This
 * is the cross-version compatibility property RFC 0001 promises.
 */

import { canonicalize } from "../v3/canonical";
import { sha256Hex } from "../v3/canonical-hash";
import {
  importPublicKeyJwk,
  verify as verifyEd25519,
  type JwkEd25519Public,
} from "../v3/crypto";
import {
  verifyLocal as verifyLocalV3,
  type VerifyLocalOptions as VerifyLocalOptionsV3,
} from "../v3/verify";
import { TSP_V3_VERSION } from "../v3/types";
import type { VerifyResult as VerifyResultV3 } from "../v3/types";
import {
  TSP_V4_VERSION,
  type CheckResult,
  type ProvenanceKind,
  type TrustEnvelope,
  type VerifyChecks,
  type VerifyResult,
} from "./types";

const PASS = (detail: string): CheckResult => ({ status: "passed", detail });
const FAIL = (detail: string, evidence?: unknown): CheckResult => ({
  status: "failed",
  detail,
  evidence,
});
const SKIP = (detail: string): CheckResult => ({ status: "skipped", detail });

const REGISTERED_KINDS: ReadonlySet<ProvenanceKind> = new Set([
  "ai",
  "credential",
  "attestation",
  "supply-chain",
]);

const textEncoder = new TextEncoder();

export interface VerifyLocalOptions {
  knownPublicKey: JwkEd25519Public;
}

export async function verifyLocal(
  envelope: TrustEnvelope,
  opts: VerifyLocalOptions,
): Promise<VerifyResult> {
  const checks: VerifyChecks = {
    schema: SKIP("not yet checked"),
    contentHash: SKIP("not yet checked"),
    ledgerHash: SKIP("not yet checked"),
    provenanceKind: SKIP("not yet checked"),
    manifestFetch: SKIP("local-only: manifest fetch not performed"),
    rootSignature: SKIP("local-only: root signature not verified"),
    certChain: SKIP("local-only: cert chain not validated"),
    certValidity: SKIP("local-only: cert validity not checked"),
    revocation: SKIP("local-only: revocation not checked"),
    tsa: SKIP("local-only: TSA token not verified"),
    signatures: [],
  };
  const warnings: string[] = [];

  // 1. Schema — must be v4-draft AND have all required top-level fields.
  if (envelope.tsp !== TSP_V4_VERSION) {
    checks.schema = FAIL(`expected tsp="${TSP_V4_VERSION}", got "${envelope.tsp}"`);
  } else if (
    !envelope.content ||
    !envelope.provenance ||
    !envelope.qa ||
    !envelope.signatures ||
    envelope.signatures.length === 0
  ) {
    checks.schema = FAIL("envelope missing required fields (content/provenance/qa/signatures)");
  } else {
    checks.schema = PASS("schema is well-formed");
  }

  // 2. Provenance kind — must be one of the registered kinds.
  if (envelope.provenance && REGISTERED_KINDS.has(envelope.provenance.kind)) {
    checks.provenanceKind = PASS(
      `provenance.kind="${envelope.provenance.kind}" is registered`,
    );
  } else {
    checks.provenanceKind = FAIL(
      `provenance.kind="${envelope.provenance?.kind}" is not registered`,
    );
  }

  // 3. Content hash.
  const expectedContentHash = await sha256Hex(canonicalize(envelope.content.value));
  if (expectedContentHash === envelope.content.hash) {
    checks.contentHash = PASS("content hash matches canonical(value)");
  } else {
    checks.contentHash = FAIL(
      `content hash mismatch: claimed ${envelope.content.hash}, computed ${expectedContentHash}`,
    );
  }

  // 4. Ledger hash — recompute over (envelope − ledger.hash) with v4 shape.
  const ledgerDomain: Record<string, unknown> = {
    tsp: envelope.tsp,
    content: envelope.content,
    declaration: envelope.declaration,
    provenance: envelope.provenance,
    qa: envelope.qa,
    timestamp: envelope.timestamp,
    signatures: envelope.signatures,
    ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash },
  };
  const expectedLedgerHash = await sha256Hex(canonicalize(ledgerDomain));
  if (expectedLedgerHash === envelope.ledger.hash) {
    checks.ledgerHash = PASS("ledger hash matches canonical(envelope − ledger.hash)");
  } else {
    checks.ledgerHash = FAIL(
      `ledger hash mismatch: claimed ${envelope.ledger.hash}, computed ${expectedLedgerHash}`,
    );
  }

  // 5. Signatures — must reconstruct sigDomain identically to wrap().
  for (const sig of envelope.signatures) {
    if (sig.algorithm !== "ed25519") {
      checks.signatures.push(FAIL(`unsupported algorithm: ${sig.algorithm}`));
      continue;
    }

    const sigDomain: Record<string, unknown> = {
      tsp: envelope.tsp,
      content: envelope.content,
      declaration: envelope.declaration,
      provenance: envelope.provenance,
      qa: envelope.qa,
      timestamp: { claimed: envelope.timestamp.claimed, tsaUrl: envelope.timestamp.tsaUrl },
      ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash },
    };

    let publicKey;
    try {
      publicKey = await importPublicKeyJwk(opts.knownPublicKey);
    } catch (e) {
      checks.signatures.push(FAIL(`could not import known public key: ${String(e)}`));
      continue;
    }

    let sigBytes: Uint8Array;
    try {
      sigBytes = Uint8Array.from(atob(sig.signature), (c) => c.charCodeAt(0));
    } catch (e) {
      checks.signatures.push(FAIL(`signature is not valid base64: ${String(e)}`));
      continue;
    }

    const ok = await verifyEd25519(
      publicKey,
      sigBytes,
      textEncoder.encode(canonicalize(sigDomain)),
    );
    checks.signatures.push(
      ok
        ? PASS(`signature valid (role=${sig.role}, algorithm=${sig.algorithm})`)
        : FAIL(`signature invalid (role=${sig.role}, algorithm=${sig.algorithm})`),
    );
  }

  warnings.push(
    "v4 EXPERIMENTAL: only schema, contentHash, ledgerHash, provenanceKind, " +
      "and signatures are checked in this preview. Manifest/cert/TSA checks " +
      "reuse the v3 PKI layer unchanged; wiring them through v4 is deferred " +
      "until RFC 0001 is accepted.",
  );

  const requiredChecks: CheckResult[] = [
    checks.schema,
    checks.provenanceKind,
    checks.contentHash,
    checks.ledgerHash,
    ...checks.signatures,
  ];
  const valid = requiredChecks.every((c) => c.status === "passed");

  return { valid, envelope, checks, warnings };
}

/**
 * Cross-version dispatch. Inspects `envelope.tsp` and routes to the
 * appropriate verifier. v4 verifiers MUST accept valid v3 envelopes;
 * this function is how that contract is satisfied.
 *
 * The return type is intentionally a discriminated union of v3 and v4
 * `VerifyResult` so callers can type-narrow on the version they got.
 */
export async function verifyAny(
  envelope: unknown,
  opts: VerifyLocalOptions,
): Promise<
  | { version: "3.0"; result: VerifyResultV3 }
  | { version: "4.0-draft"; result: VerifyResult }
  | { version: "unknown"; reason: string }
> {
  if (typeof envelope !== "object" || envelope === null || !("tsp" in envelope)) {
    return { version: "unknown", reason: "envelope is not an object or missing tsp field" };
  }
  const tsp = (envelope as { tsp: unknown }).tsp;
  if (tsp === TSP_V3_VERSION) {
    const v3Opts: VerifyLocalOptionsV3 = { knownPublicKey: opts.knownPublicKey };
    const result = await verifyLocalV3(envelope as Parameters<typeof verifyLocalV3>[0], v3Opts);
    return { version: "3.0", result };
  }
  if (tsp === TSP_V4_VERSION) {
    const result = await verifyLocal(envelope as TrustEnvelope, opts);
    return { version: "4.0-draft", result };
  }
  return { version: "unknown", reason: `unsupported tsp version: ${String(tsp)}` };
}
