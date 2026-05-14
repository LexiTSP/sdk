/**
 * RFC 8785 — JSON Canonicalization Scheme (JCS).
 *
 * Strict implementation that produces deterministic output across
 * languages and platforms. Reference: https://datatracker.ietf.org/doc/html/rfc8785
 *
 * Number serialization delegates to JSON.stringify, which in V8/JSC/SpiderMonkey
 * conforms to ECMA-262 §7.1.12.1 for finite numbers (matching RFC 8785 §3.2.2.3).
 */

const REQUIRES_ESCAPE = /[\x00-\x1f"\\]/g;

const ESCAPE_MAP: Record<string, string> = {
  "\b": "\\b",
  "\t": "\\t",
  "\n": "\\n",
  "\f": "\\f",
  "\r": "\\r",
  '"': '\\"',
  "\\": "\\\\",
};

function escapeChar(c: string): string {
  if (c in ESCAPE_MAP) return ESCAPE_MAP[c];
  const code = c.charCodeAt(0);
  return "\\u" + code.toString(16).padStart(4, "0");
}

function canonicalString(s: string): string {
  return '"' + s.replace(REQUIRES_ESCAPE, escapeChar) + '"';
}

function canonicalNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error(`canonicalize: non-finite number not allowed: ${n}`);
  }
  // Object.is to handle -0 → "0" per RFC 8785
  if (Object.is(n, -0)) return "0";
  return JSON.stringify(n);
}

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return canonicalNumber(value);
  if (typeof value === "string") return canonicalString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => {
      if (a < b) return -1;
      if (a > b) return 1;
      return 0;
    });
    return (
      "{" +
      keys.map((k) => canonicalString(k) + ":" + canonicalize(obj[k])).join(",") +
      "}"
    );
  }
  throw new Error(`canonicalize: unsupported value type: ${typeof value}`);
}
