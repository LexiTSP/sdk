/**
 * @lexitsp/sdk v3 · verifyOnline
 *
 * Full network-aware verification.
 * Fail-closed on network errors per spec decision Q2.3/B.
 */

import { canonicalize } from "./canonical";
import { sha256Hex } from "./canonical-hash";
import { importPublicKeyJwk, verify as verifyEd25519 } from "./crypto";
import type {
  TrustEnvelope,
  VerifyResult,
  CheckResult,
} from "./types";
import { TSP_V3_VERSION } from "./types";
import { fetchManifest } from "./manifest-fetch";
import { verifyManifestSignature, verifyInstanceCert } from "./manifest-verify";
import { isCertValidAt } from "./cert";
import { checkRevocation } from "./revocation";
import { checkSequence, recordSequence } from "./sequence-state";
import { verifyTsaToken } from "./tsa-verify";
import type { TrustedTsa } from "./tsa-trust";
import { verifyDane, type DaneOptions } from "./dane";
import { TSA_PLACEHOLDER_TOKEN } from "./envelope";

const PASS = (detail: string): CheckResult => ({ status: "passed", detail });
const FAIL = (detail: string, evidence?: unknown): CheckResult => ({ status: "failed", detail, evidence });
const SKIP = (detail: string): CheckResult => ({ status: "skipped", detail });

const enc = new TextEncoder();

export interface VerifyOnlineOptions {
  fetch?: typeof globalThis.fetch;
  ttlMs?: number;
  acceptableManifestAgeOverride?: number;
  requireDane?: boolean;
  /** Per Phase 3 Q3.2/C: opt-in for legacy alpha envelopes with placeholder tsaToken. */
  acceptLegacyTsa?: boolean;
  /** Per Phase 3 Q3.4/B: explicit TSA cert-fingerprint trust list. Default empty. */
  trustedTsas?: TrustedTsa[];
  /** Options forwarded to verifyDane when requireDane is true. */
  daneOptions?: DaneOptions;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2) throw new Error("hex string must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function deriveManifestUrl(keyRef: string): { url: string; instanceId: string; domain: string } {
  const hashIdx = keyRef.indexOf("#");
  if (hashIdx === -1) throw new Error(`keyRef missing fragment: ${keyRef}`);
  const url = keyRef.slice(0, hashIdx);
  const instanceId = keyRef.slice(hashIdx + 1);
  const u = new URL(url);
  return { url, instanceId, domain: u.hostname };
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export async function verifyOnline(
  envelope: TrustEnvelope,
  opts: VerifyOnlineOptions = {}
): Promise<VerifyResult> {
  const checks: VerifyResult["checks"] = {
    schema: SKIP("not yet checked"),
    contentHash: SKIP("not yet checked"),
    ledgerHash: SKIP("not yet checked"),
    manifestFetch: SKIP("not yet checked"),
    rootSignature: SKIP("not yet checked"),
    certChain: SKIP("not yet checked"),
    certValidity: SKIP("not yet checked"),
    revocation: SKIP("not yet checked"),
    tsa: SKIP("not yet checked"),
    signatures: [],
  };
  const warnings: string[] = [];

  if (opts.requireDane) {
    checks.dane = SKIP("DANE check not yet performed");
  }

  // 1. Schema
  if (envelope.tsp !== TSP_V3_VERSION) {
    checks.schema = FAIL(`expected tsp="${TSP_V3_VERSION}", got "${envelope.tsp}"`);
    return finalize(envelope, checks, warnings);
  }
  if (!envelope.content || !envelope.signatures || envelope.signatures.length === 0) {
    checks.schema = FAIL("envelope missing required fields");
    return finalize(envelope, checks, warnings);
  }
  checks.schema = PASS("schema is well-formed");

  // 2. content.hash
  const expectedContentHash = await sha256Hex(canonicalize(envelope.content.value));
  checks.contentHash =
    expectedContentHash === envelope.content.hash
      ? PASS("content hash matches canonical(value)")
      : FAIL(`content hash mismatch: claimed ${envelope.content.hash}, computed ${expectedContentHash}`);

  // 3. ledger.hash
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
  checks.ledgerHash =
    expectedLedgerHash === envelope.ledger.hash
      ? PASS("ledger hash matches canonical(envelope − ledger.hash)")
      : FAIL(`ledger hash mismatch: claimed ${envelope.ledger.hash}, computed ${expectedLedgerHash}`);

  // 4. Manifest fetch
  const sig = envelope.signatures[0];
  let manifestUrl: string;
  let instanceId: string;
  let domain: string;
  try {
    const parsed = deriveManifestUrl(sig.keyRef);
    manifestUrl = parsed.url;
    instanceId = parsed.instanceId;
    domain = parsed.domain;
  } catch (e) {
    checks.manifestFetch = FAIL(`could not parse keyRef: ${String(e)}`);
    return finalize(envelope, checks, warnings);
  }

  let fetchResult;
  try {
    fetchResult = await fetchManifest(manifestUrl, { fetch: opts.fetch, ttlMs: opts.ttlMs });
  } catch (e) {
    checks.manifestFetch = FAIL(`fetch failed: ${String(e)}`);
    return finalize(envelope, checks, warnings);
  }
  const manifest = fetchResult.manifest;

  // 4b. Sequence rollback check
  const seqCheck = checkSequence(domain, manifest.sequence);
  if (seqCheck.rollback) {
    checks.manifestFetch = FAIL(
      `rollback detected: cached sequence ${seqCheck.highestSeen}, received ${seqCheck.received}`
    );
    return finalize(envelope, checks, warnings);
  }

  // 4c. Manifest age check
  const issuedAtMs = Date.parse(manifest.issuedAt);
  const ageSeconds = Math.floor((Date.now() - issuedAtMs) / 1000);
  const maxAge = opts.acceptableManifestAgeOverride ?? manifest.acceptableAge.seconds;
  if (ageSeconds > maxAge) {
    checks.manifestFetch = FAIL(`manifest is stale: ${ageSeconds}s old, max ${maxAge}s`);
    return finalize(envelope, checks, warnings);
  }

  const cacheDetail = fetchResult.fromCache
    ? fetchResult.revalidated
      ? `cached, revalidated via ETag, age: ${ageSeconds}s`
      : `cached, age: ${ageSeconds}s`
    : `freshly fetched, manifest age: ${ageSeconds}s`;
  checks.manifestFetch = PASS(cacheDetail);

  // 5. Root signature on manifest
  const rootSigOk = await verifyManifestSignature(manifest);
  if (!rootSigOk) {
    checks.rootSignature = FAIL("manifest rootSignatureOverManifest does not validate");
    return finalize(envelope, checks, warnings);
  }
  checks.rootSignature = PASS("manifest signature valid");

  recordSequence(domain, manifest.sequence);

  // 6. Cert chain
  const instance = manifest.instances.find((i) => i.id === instanceId);
  if (!instance) {
    checks.certChain = FAIL(`instance "${instanceId}" not in manifest`);
    return finalize(envelope, checks, warnings);
  }
  const certOk = await verifyInstanceCert(instance, manifest.rootKey);
  if (!certOk) {
    checks.certChain = FAIL(`instance cert "${instanceId}" rootSignature does not validate`);
    return finalize(envelope, checks, warnings);
  }
  checks.certChain = PASS(`instance cert "${instanceId}" signed by org-root`);

  // 7. Cert validity window
  const validityResult = isCertValidAt(instance, envelope.timestamp.claimed);
  checks.certValidity = validityResult.valid
    ? PASS(`envelope timestamp within cert validity window`)
    : FAIL(validityResult.reason ?? "cert not valid at envelope timestamp");

  // 8. Revocation
  const revResult = checkRevocation(instanceId, envelope.timestamp.claimed, manifest.revoked);
  if (revResult.status === "not-revoked" || revResult.status === "predates-revocation") {
    checks.revocation = PASS(revResult.detail);
  } else {
    checks.revocation = FAIL(revResult.detail);
  }

  // 9. TSA token (Phase 3)
  if (envelope.timestamp.tsaToken === TSA_PLACEHOLDER_TOKEN) {
    if (opts.acceptLegacyTsa) {
      checks.tsa = SKIP("legacy alpha placeholder token, accepted via acceptLegacyTsa");
      warnings.push("envelope has legacy placeholder tsaToken; no real TSA attestation");
    } else {
      checks.tsa = FAIL("legacy placeholder tsaToken; pass acceptLegacyTsa: true to allow");
    }
  } else {
    const tsaInputDomain: Record<string, unknown> = {
      tsp: envelope.tsp,
      content: envelope.content,
      declaration: envelope.declaration,
      process: envelope.process,
      alignment: envelope.alignment,
      timestamp: { claimed: envelope.timestamp.claimed, tsaUrl: envelope.timestamp.tsaUrl },
      ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash },
      signatures: envelope.signatures,
    };
    const expectedTsaHash = hexToBytes(await sha256Hex(canonicalize(tsaInputDomain)));
    const tsaResult = await verifyTsaToken(envelope.timestamp.tsaToken, expectedTsaHash, opts.trustedTsas);
    checks.tsa = tsaResult.valid ? PASS(tsaResult.reason) : FAIL(tsaResult.reason);
  }

  // 10. DANE (optional)
  if (opts.requireDane) {
    const daneResult = await verifyDane(domain, manifest.rootKey, opts.daneOptions);
    checks.dane = daneResult.valid ? PASS(daneResult.reason) : FAIL(daneResult.reason);
  }

  // 11. Signature verification
  for (const s of envelope.signatures) {
    if (s.algorithm !== "ed25519") {
      checks.signatures.push(FAIL(`unsupported algorithm: ${s.algorithm}`));
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
    let pubKey;
    try {
      pubKey = await importPublicKeyJwk(instance.publicKey);
    } catch (e) {
      checks.signatures.push(FAIL(`could not import instance public key: ${String(e)}`));
      continue;
    }
    let sigBytes: Uint8Array;
    try {
      sigBytes = base64ToBytes(s.signature);
    } catch (e) {
      checks.signatures.push(FAIL(`signature is not valid base64: ${String(e)}`));
      continue;
    }
    const ok = await verifyEd25519(pubKey, sigBytes, enc.encode(canonicalize(sigDomain)));
    checks.signatures.push(
      ok ? PASS(`signature valid (role=${s.role})`) : FAIL(`signature invalid (role=${s.role})`)
    );
  }

  return finalize(envelope, checks, warnings);
}

function finalize(
  envelope: TrustEnvelope,
  checks: VerifyResult["checks"],
  warnings: string[]
): VerifyResult {
  const mustPass: CheckResult[] = [
    checks.schema,
    checks.contentHash,
    checks.ledgerHash,
    checks.manifestFetch,
    checks.rootSignature,
    checks.certChain,
    checks.certValidity,
    checks.revocation,
    ...checks.signatures,
  ];
  // tsa: passed OR skipped (skipped happens only with acceptLegacyTsa)
  const tsaOk = checks.tsa.status === "passed" || checks.tsa.status === "skipped";
  // dane: only required when present (set when requireDane was true)
  const daneOk = checks.dane === undefined || checks.dane.status === "passed";

  const valid = mustPass.every((c) => c.status === "passed") && tsaOk && daneOk;
  return { valid, envelope, checks, warnings };
}
