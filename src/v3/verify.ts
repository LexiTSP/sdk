/**
 * @lexitsp/sdk v3 · verify
 *
 * Phase 1 implements only the local-only path: schema + content hash +
 * ledger hash + signature. Manifest fetch, cert-chain, TSA, and DANE
 * are skipped (status: "skipped"). Phase 2/3 add those.
 */

import { canonicalize } from "./canonical";
import { sha256Hex } from "./canonical-hash";
import {
  importPublicKeyJwk,
  verify as verifyEd25519,
  type JwkEd25519Public,
} from "./crypto";
import type {
  TrustEnvelope,
  VerifyResult,
  CheckResult,
} from "./types";
import { TSP_V3_VERSION } from "./types";

const PASS = (detail: string): CheckResult => ({ status: "passed", detail });
const FAIL = (detail: string, evidence?: unknown): CheckResult => ({
  status: "failed",
  detail,
  evidence,
});
const SKIP = (detail: string): CheckResult => ({ status: "skipped", detail });

const textEncoder = new TextEncoder();

export interface VerifyLocalOptions {
  /** The public key to verify the instance signature against. */
  knownPublicKey: JwkEd25519Public;
}

export async function verifyLocal(
  envelope: TrustEnvelope,
  opts: VerifyLocalOptions
): Promise<VerifyResult> {
  const checks: VerifyResult["checks"] = {
    schema: SKIP("not yet checked"),
    contentHash: SKIP("not yet checked"),
    ledgerHash: SKIP("not yet checked"),
    manifestFetch: SKIP("local-only mode: manifest fetch not performed"),
    rootSignature: SKIP("local-only mode: root signature not verified"),
    certChain: SKIP("local-only mode: cert chain not validated"),
    certValidity: SKIP("local-only mode: cert validity not checked"),
    revocation: SKIP("local-only mode: revocation not checked"),
    tsa: SKIP("local-only mode: TSA token not verified"),
    signatures: [],
  };
  const warnings: string[] = [];

  // 1. Schema
  if (envelope.tsp !== TSP_V3_VERSION) {
    checks.schema = FAIL(`expected tsp="${TSP_V3_VERSION}", got "${envelope.tsp}"`);
  } else if (!envelope.content || !envelope.signatures || envelope.signatures.length === 0) {
    checks.schema = FAIL("envelope missing required fields");
  } else {
    checks.schema = PASS("schema is well-formed");
  }

  // 2. content.hash
  const expectedContentHash = await sha256Hex(canonicalize(envelope.content.value));
  if (expectedContentHash === envelope.content.hash) {
    checks.contentHash = PASS("content hash matches canonical(value)");
  } else {
    checks.contentHash = FAIL(
      `content hash mismatch: claimed ${envelope.content.hash}, computed ${expectedContentHash}`
    );
  }

  // 3. ledger.hash — recompute over (envelope − ledger.hash)
  const ledgerDomain: Record<string, unknown> = {
    tsp: envelope.tsp,
    content: envelope.content,
    declaration: envelope.declaration,
    process: envelope.process,
    alignment: envelope.alignment,
    timestamp: envelope.timestamp,
    signatures: envelope.signatures,
    ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash },
  };
  const expectedLedgerHash = await sha256Hex(canonicalize(ledgerDomain));
  if (expectedLedgerHash === envelope.ledger.hash) {
    checks.ledgerHash = PASS("ledger hash matches canonical(envelope − ledger.hash)");
  } else {
    checks.ledgerHash = FAIL(
      `ledger hash mismatch: claimed ${envelope.ledger.hash}, computed ${expectedLedgerHash}`
    );
  }

  // 11. Signatures — must reconstruct sigDomain identically to wrap()
  for (const sig of envelope.signatures) {
    if (sig.algorithm !== "ed25519") {
      checks.signatures.push(FAIL(`unsupported algorithm: ${sig.algorithm}`));
      continue;
    }

    const sigDomain: Record<string, unknown> = {
      tsp: envelope.tsp,
      content: envelope.content,
      declaration: envelope.declaration,
      process: envelope.process,
      alignment: envelope.alignment,
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
      textEncoder.encode(canonicalize(sigDomain))
    );
    checks.signatures.push(
      ok
        ? PASS(`signature valid (role=${sig.role}, algorithm=${sig.algorithm})`)
        : FAIL(`signature invalid (role=${sig.role}, algorithm=${sig.algorithm})`)
    );
  }

  warnings.push(
    "local-only verify: manifest, cert-chain, TSA, and revocation checks are not performed in Phase 1"
  );

  const requiredChecks: CheckResult[] = [
    checks.schema,
    checks.contentHash,
    checks.ledgerHash,
    ...checks.signatures,
  ];
  const valid = requiredChecks.every((c) => c.status === "passed");

  return { valid, envelope, checks, warnings };
}
