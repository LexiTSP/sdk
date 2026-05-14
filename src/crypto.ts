/**
 * @lexitsp/sdk · crypto
 *
 * SHA-256 hashing and canonical JSON serialization (RFC 8785-style).
 * Uses Web Crypto API — works in Node 18+, Bun, browsers, and edge runtimes.
 */

const encoder = new TextEncoder();

/**
 * Compute SHA-256 hex digest of a string input.
 */
export async function sha256(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

/**
 * Canonical JSON serialization — deterministic across implementations.
 *
 * Rules:
 * - Object keys sorted alphabetically
 * - Arrays preserve order
 * - No insignificant whitespace
 * - Standard JSON escaping for strings and numbers (delegated to JSON.stringify)
 *
 * This guarantees that the same envelope produces the same hash regardless
 * of language, platform, or implementation. Compatible with RFC 8785 (JCS).
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k]))
      .join(",") +
    "}"
  );
}
