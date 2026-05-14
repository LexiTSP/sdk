/**
 * @lexitsp/sdk v3 · DNS DANE via DNS-over-HTTPS
 *
 * Per spec decision Q3.3/A, DANE is verifier-side only and opt-in.
 * We use DoH (Cloudflare default) to get DNSSEC validation via the AD flag.
 */

import { canonicalize } from "./canonical";
import { sha256Hex } from "./canonical-hash";
import type { JwkEd25519Public } from "./crypto";

export interface DaneOptions {
  dohEndpoint?: string;            // default Cloudflare 1.1.1.1
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;              // default 5000
}

export interface DaneResult {
  valid: boolean;
  reason: string;
  manifestUrlFromDns?: string;
}

interface DohResponse {
  Status: number;
  AD?: boolean;
  Answer?: Array<{ name: string; type: number; data: string }>;
}

function parseTxtRecord(data: string): Record<string, string> {
  // DoH wraps TXT data in quotes; strip them
  const stripped = data.replace(/^"|"$/g, "");
  const out: Record<string, string> = {};
  for (const part of stripped.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
}

export async function verifyDane(
  domain: string,
  manifestRootKey: JwkEd25519Public,
  opts: DaneOptions = {}
): Promise<DaneResult> {
  const endpoint = opts.dohEndpoint ?? "https://1.1.1.1/dns-query";
  const fetchFn = opts.fetch ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 5000;

  const url = `${endpoint}?name=_tsp.${encodeURIComponent(domain)}&type=TXT`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetchFn(url, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(timer);
    return { valid: false, reason: `DoH request failed: ${(e as Error).message}` };
  }
  clearTimeout(timer);

  if (!response.ok) {
    return { valid: false, reason: `DoH returned HTTP ${response.status}` };
  }

  let body: DohResponse;
  try {
    body = (await response.json()) as DohResponse;
  } catch (e) {
    return { valid: false, reason: `DoH response not valid JSON: ${(e as Error).message}` };
  }

  if (body.Status !== 0) {
    return { valid: false, reason: `DNS query returned status ${body.Status}` };
  }

  if (body.AD !== true) {
    return {
      valid: false,
      reason: `DNSSEC validation flag (AD) is false; DANE requires DNSSEC-signed records`,
    };
  }

  if (!body.Answer || body.Answer.length === 0) {
    return { valid: false, reason: `no _tsp TXT record found for ${domain}` };
  }

  // Find a record matching v=tsp1
  for (const ans of body.Answer) {
    if (ans.type !== 16) continue; // TXT
    const fields = parseTxtRecord(ans.data);
    if (fields.v !== "tsp1") continue;
    if (!fields.rootKeyHash) continue;

    const expectedHash = await sha256Hex(canonicalize(manifestRootKey));
    // rootKeyHash is "sha256-<base64>" or "sha256-<hex>"; we accept both.
    const expected = fields.rootKeyHash.replace(/^sha256-/, "").toLowerCase();
    if (expected === expectedHash || isBase64MatchingHex(expected, expectedHash)) {
      return {
        valid: true,
        reason: `DANE TXT record validated; rootKey fingerprint matches`,
        manifestUrlFromDns: fields.manifest,
      };
    }
    return {
      valid: false,
      reason: `DANE rootKeyHash (${expected}) does not match manifest rootKey hash (${expectedHash})`,
    };
  }

  return { valid: false, reason: `no TXT record with v=tsp1 found` };
}

function isBase64MatchingHex(b64: string, hex: string): boolean {
  try {
    const decoded = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    let asHex = "";
    for (const b of decoded) asHex += b.toString(16).padStart(2, "0");
    return asHex === hex;
  } catch {
    return false;
  }
}
