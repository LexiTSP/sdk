/**
 * @lexitsp/sdk v4 · envelope — EXPERIMENTAL
 *
 * wrap() for TSP/4.0-draft envelopes. Reuses v3's canonical-JSON,
 * SHA-256, Ed25519, and TSA modules verbatim — the substrate primitives
 * are unchanged. Only the envelope shape and signing-domain selection
 * are v4-specific.
 *
 * Construction order mirrors v3:
 *   1. Compute content hash
 *   2. Build base envelope (placeholder tsaToken, empty signatures, empty ledger.hash)
 *   3. Compute signature over (envelope − signatures − ledger.hash − timestamp.tsaToken)
 *   4. Stamp TSA (Phase 3 — reused from v3/tsa.ts)
 *   5. Compute ledger.hash over (envelope − ledger.hash)
 */

import { canonicalize } from "../v3/canonical";
import { sha256Hex } from "../v3/canonical-hash";
import type { JwkEd25519Public } from "../v3/crypto";
import { stampHash, type TsaClientOptions } from "../v3/tsa";
import {
  TSP_V4_VERSION,
  type Content,
  type Declaration,
  type Provenance,
  type ProvenanceKind,
  type QA,
  type SignatureEntry,
  type TrustEnvelope,
} from "./types";

export type { JwkEd25519Public } from "../v3/crypto";

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
  provenance: Provenance;
  qa: QA;
  prevHash: string;
  /** Optional override for testing; defaults to current time. */
  now?: Date;
  tsaUrls?: string[];
  tsaTimeoutMs?: number;
  fetch?: typeof globalThis.fetch;
  skipTsa?: boolean;
}

export const TSA_PLACEHOLDER_TOKEN = "__phase1__";
export const TSA_PLACEHOLDER_URL = "https://placeholder.invalid/phase1";

const REGISTERED_KINDS: ReadonlySet<ProvenanceKind> = new Set([
  "ai",
  "credential",
  "attestation",
  "supply-chain",
]);

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
  return typeof process !== "undefined" && process.env && process.env.NODE_ENV === "production";
}

function defaultTsaUrls(): string[] {
  if (isProduction()) {
    throw new Error(
      "v4 wrap() requires explicit TSA configuration in production, but v4 is " +
        "currently EXPERIMENTAL (RFC 0001 draft) and MUST NOT be used for " +
        "production issuance. Set { skipTsa: true } if you intentionally " +
        "want a placeholder TSA token for non-production fixtures.",
    );
  }
  return [];
}

/**
 * Builds and signs a v4 TrustEnvelope.
 *
 * Refuses any `provenance.kind` not in the registered set
 * (see RFC 0001 §"Registry of kind values"). Throws synchronously
 * because issuing a malformed envelope is a programmer error, not a
 * recoverable runtime condition.
 */
export async function wrap(
  input: WrapInput,
  opts: WrapOptions,
): Promise<TrustEnvelope> {
  if (!REGISTERED_KINDS.has(opts.provenance.kind)) {
    throw new Error(
      `unknown provenance.kind "${opts.provenance.kind}" — registered kinds are: ${[
        ...REGISTERED_KINDS,
      ].join(", ")}. New kinds require their own RFC.`,
    );
  }

  const localNow = (opts.now ?? new Date()).toISOString();

  const contentHash = await sha256Hex(canonicalize(input.value));

  const envelope: TrustEnvelope = {
    tsp: TSP_V4_VERSION,
    content: { type: input.type, value: input.value, hash: contentHash },
    declaration: opts.declaration,
    provenance: opts.provenance,
    qa: opts.qa,
    timestamp: {
      claimed: localNow,
      tsaToken: TSA_PLACEHOLDER_TOKEN,
      tsaUrl: TSA_PLACEHOLDER_URL,
    },
    ledger: { id: uuidv7(), prevHash: opts.prevHash, hash: "" },
    signatures: [],
  };

  const sigDomain: Record<string, unknown> = {
    tsp: envelope.tsp,
    content: envelope.content,
    declaration: envelope.declaration,
    provenance: envelope.provenance,
    qa: envelope.qa,
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

  if (!opts.skipTsa) {
    const tsaUrls = opts.tsaUrls ?? defaultTsaUrls();
    if (tsaUrls.length === 0) {
      console.warn(
        "[@lexitsp/sdk/v4] wrap() running with no TSA configured. " +
          "Envelope will use placeholder tsaToken. v4 is EXPERIMENTAL " +
          "(RFC 0001 draft) and MUST NOT be issued for production.",
      );
    } else {
      const tsaInputDomain: Record<string, unknown> = {
        tsp: envelope.tsp,
        content: envelope.content,
        declaration: envelope.declaration,
        provenance: envelope.provenance,
        qa: envelope.qa,
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
  envelope.ledger.hash = await sha256Hex(canonicalize(ledgerDomain));

  return envelope;
}
