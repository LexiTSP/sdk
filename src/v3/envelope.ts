/**
 * @lexitsp/sdk v3 · envelope construction
 *
 * wrap() builds a TSP v3.0 TrustEnvelope, signs it, and (Phase 3) timestamps
 * it via an RFC 3161 TSA. If no TSA URLs are configured:
 *   - In production (NODE_ENV === "production"): wrap() throws.
 *   - In dev: a placeholder token "__phase1__" is used and a warning is logged.
 *
 * Construction order (corrected from Phase 1 spec):
 *   1. Compute content hash
 *   2. Build base envelope (placeholder tsaToken, empty signatures, empty ledger.hash)
 *   3. Compute signature over (envelope − signatures − ledger.hash − timestamp.tsaToken), set
 *   4. Compute TSA-input-hash = sha256(canonical(envelope − timestamp.tsaToken)),
 *      call TSA, set timestamp.tsaToken / tsaUrl / claimed (TSA's genTime)
 *   5. Compute ledger.hash over (envelope − ledger.hash) — now commits to real TSA token
 */

import { canonicalize } from "./canonical";
import { sha256Hex } from "./canonical-hash";
import type {
  Declaration,
  Process,
  Alignment,
  Content,
  TrustEnvelope,
  SignatureEntry,
} from "./types";
import { TSP_V3_VERSION } from "./types";
import type { JwkEd25519Public } from "./crypto";
import { stampHash, type TsaClientOptions } from "./tsa";

export type { JwkEd25519Public } from "./crypto";

export interface Signer {
  sign(data: Uint8Array): Promise<Uint8Array>;
  publicKey: JwkEd25519Public;
  keyRef: string;
  certChain: string[];
}

export interface WrapInput {
  type: Content["type"];
  value: string;
}

export interface WrapOptions {
  signer: Signer;
  declaration: Declaration;
  process: Process;
  alignment: Alignment;
  prevHash: string;
  /** Optional override for testing; defaults to current time. Used as fallback claimed when TSA unavailable. */
  now?: Date;
  /** TSA URLs in priority order. Required in production. Dev falls back to FreeTSA with warning. */
  tsaUrls?: string[];
  /** Per-TSA HTTP timeout (ms). Default 10000. */
  tsaTimeoutMs?: number;
  /** Override fetch (for testing). */
  fetch?: typeof globalThis.fetch;
  /** If true, skip TSA call and use placeholder token. Implicit in non-production when tsaUrls is empty. */
  skipTsa?: boolean;
  /**
   * Optional dual-write to a Risk-module endpoint. After the envelope is fully
   * constructed, fire-and-forget POST to riskSink.url with the envelope JSON.
   * Errors are handled per onError ("warn" | "throw" | "ignore"), default "warn".
   * Never blocks the primary wrap() return path.
   */
  riskSink?: RiskSinkConfig;
}

export interface RiskSinkConfig {
  url: string;
  apiKey: string;
  onError?: "warn" | "throw" | "ignore";
  /** Override fetch (for testing). */
  fetch?: typeof globalThis.fetch;
}

export const TSA_PLACEHOLDER_TOKEN = "__phase1__";
export const TSA_PLACEHOLDER_URL = "https://placeholder.invalid/phase1";

function uuidv7(): string {
  const ts = BigInt(Date.now());
  const hex = ts.toString(16).padStart(12, "0");
  const rand = crypto.getRandomValues(new Uint8Array(10));
  rand[0] = (rand[0] & 0x0f) | 0x70;
  rand[2] = (rand[2] & 0x3f) | 0x80;
  let randHex = "";
  for (let i = 0; i < rand.length; i++) randHex += rand[i].toString(16).padStart(2, "0");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    randHex.slice(0, 4),
    randHex.slice(4, 8),
    randHex.slice(8, 20),
  ].join("-");
}

const textEncoder = new TextEncoder();

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2) throw new Error("hex string must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function isProduction(): boolean {
  // process.env access guarded for non-Node runtimes
  return typeof process !== "undefined" && process.env && process.env.NODE_ENV === "production";
}

export async function wrap(
  input: WrapInput,
  opts: WrapOptions
): Promise<TrustEnvelope> {
  const localNow = (opts.now ?? new Date()).toISOString();

  // 1. Content hash
  const contentHash = await sha256Hex(canonicalize(input.value));

  // 2. Base envelope
  const envelope: TrustEnvelope = {
    tsp: TSP_V3_VERSION,
    content: { type: input.type, value: input.value, hash: contentHash },
    declaration: opts.declaration,
    process: opts.process,
    alignment: opts.alignment,
    timestamp: {
      claimed: localNow,
      tsaToken: TSA_PLACEHOLDER_TOKEN,
      tsaUrl: TSA_PLACEHOLDER_URL,
    },
    ledger: { id: uuidv7(), prevHash: opts.prevHash, hash: "" },
    signatures: [],
  };

  // 3. Signature over (envelope − signatures − ledger.hash − timestamp.tsaToken)
  const sigDomain: Record<string, unknown> = {
    tsp: envelope.tsp,
    content: envelope.content,
    declaration: envelope.declaration,
    process: envelope.process,
    alignment: envelope.alignment,
    timestamp: { claimed: envelope.timestamp.claimed, tsaUrl: envelope.timestamp.tsaUrl },
    ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash },
  };
  const sigBytes = await opts.signer.sign(textEncoder.encode(canonicalize(sigDomain)));

  const signatureEntry: SignatureEntry = {
    role: "instance",
    algorithm: "ed25519",
    keyRef: opts.signer.keyRef,
    signature: bytesToBase64(sigBytes),
    certChain: opts.signer.certChain,
  };
  envelope.signatures = [signatureEntry];

  // 4. TSA stamp (Phase 3)
  if (!opts.skipTsa) {
    const tsaUrls = opts.tsaUrls ?? defaultTsaUrls();
    if (tsaUrls.length === 0) {
      // Dev with no URLs and skipTsa not set: log + use placeholder
      console.warn(
        "[@lexitsp/sdk/v3] wrap() running with no TSA configured. Envelope will use placeholder tsaToken. Configure tsaUrls in production."
      );
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
      const tsaInputHash = hexToBytes(await sha256Hex(canonicalize(tsaInputDomain)));

      const stampOpts: TsaClientOptions = { urls: tsaUrls };
      if (opts.tsaTimeoutMs !== undefined) stampOpts.timeoutMs = opts.tsaTimeoutMs;
      if (opts.fetch !== undefined) stampOpts.fetch = opts.fetch;

      const stamp = await stampHash(tsaInputHash, stampOpts);
      envelope.timestamp.tsaToken = stamp.token;
      envelope.timestamp.tsaUrl = stamp.tsaUrl;
      envelope.timestamp.claimed = stamp.genTime;
    }
  }

  // 5. Ledger hash over (envelope − ledger.hash) — now commits to real TSA token
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
  envelope.ledger.hash = await sha256Hex(canonicalize(ledgerDomain));

  if (opts.riskSink) {
    void postToRiskSink(envelope, opts.riskSink);
  }

  return envelope;
}

async function postToRiskSink(
  envelope: TrustEnvelope,
  cfg: RiskSinkConfig
): Promise<void> {
  const onError = cfg.onError ?? "warn";
  const fetchImpl = cfg.fetch ?? globalThis.fetch;
  try {
    const res = await fetchImpl(cfg.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${cfg.apiKey}`,
      },
      body: JSON.stringify(envelope),
    });
    if (!res.ok) {
      throw new Error(`riskSink POST failed: ${res.status} ${res.statusText}`);
    }
  } catch (err) {
    if (onError === "throw") throw err;
    if (onError === "warn") {
      console.warn(
        `[@lexitsp/sdk/v3] riskSink delivery failed: ${(err as Error).message}`
      );
    }
    // "ignore" → swallow
  }
}

function defaultTsaUrls(): string[] {
  if (isProduction()) {
    throw new Error(
      "wrap() requires explicit TSA configuration in production. " +
      "Set { tsaUrls: [...] } in WrapOptions, or set { skipTsa: true } for legacy behavior."
    );
  }
  // Dev: empty so the warning path is hit; we don't hardcode FreeTSA because
  // (a) network calls in tests are slow/flaky, (b) FreeTSA cert isn't in the
  // default-empty trust list. Operators that want FreeTSA in dev pass it
  // explicitly via tsaUrls.
  return [];
}
