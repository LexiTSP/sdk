import { describe, it, expect } from "vitest";
import { canonicalize } from "../../src/v3/canonical";

describe("RFC 8785 canonicalization", () => {
  describe("primitives", () => {
    it("serializes null", () => {
      expect(canonicalize(null)).toBe("null");
    });

    it("serializes booleans", () => {
      expect(canonicalize(true)).toBe("true");
      expect(canonicalize(false)).toBe("false");
    });

    it("serializes integers", () => {
      expect(canonicalize(0)).toBe("0");
      expect(canonicalize(-0)).toBe("0");
      expect(canonicalize(42)).toBe("42");
      expect(canonicalize(-17)).toBe("-17");
    });

    it("serializes floats per ECMA-262 7.1.12.1", () => {
      expect(canonicalize(1.5)).toBe("1.5");
      expect(canonicalize(1e21)).toBe("1e+21");
      expect(canonicalize(0.001)).toBe("0.001");
    });

    it("serializes strings with required JSON escapes", () => {
      expect(canonicalize("abc")).toBe('"abc"');
      expect(canonicalize('a"b')).toBe('"a\\"b"');
      expect(canonicalize("a\\b")).toBe('"a\\\\b"');
      expect(canonicalize("a\nb")).toBe('"a\\nb"');
      expect(canonicalize("a\tb")).toBe('"a\\tb"');
    });

    it("escapes control characters as \\u00XX", () => {
      expect(canonicalize("\x01")).toBe('"\\u0001"');
      expect(canonicalize("\x1f")).toBe('"\\u001f"');
    });
  });

  describe("objects", () => {
    it("sorts keys lexicographically by UTF-16 code units", () => {
      const input = { z: 1, a: 2, m: 3 };
      expect(canonicalize(input)).toBe('{"a":2,"m":3,"z":1}');
    });

    it("handles nested objects", () => {
      const input = { b: { d: 1, c: 2 }, a: 1 };
      expect(canonicalize(input)).toBe('{"a":1,"b":{"c":2,"d":1}}');
    });

    it("preserves array order", () => {
      expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
    });

    it("handles empty containers", () => {
      expect(canonicalize({})).toBe("{}");
      expect(canonicalize([])).toBe("[]");
    });
  });

  describe("RFC 8785 official test vectors", () => {
    it("vector: numbers", () => {
      const input = {
        numbers: [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
      };
      const expected =
        '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}';
      expect(canonicalize(input)).toBe(expected);
    });

    it("vector: french (UTF-8 sorts properly)", () => {
      const input = { "Düsseldorf": 1, "Köln": 2 };
      const result = canonicalize(input);
      expect(result).toBe('{"Düsseldorf":1,"Köln":2}');
    });
  });
});

import fc from "fast-check";

describe("canonicalize properties", () => {
  it("is deterministic — same input always same output", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (v) => {
        return canonicalize(v) === canonicalize(v);
      }),
      { numRuns: 1000 }
    );
  });

  it("is order-invariant for objects", () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          fc.string({ minLength: 1, maxLength: 10 }).filter((s) => !["__proto__", "constructor", "prototype"].includes(s)),
          fc.integer()
        ),
        (obj) => {
          const reordered: Record<string, number> = {};
          for (const k of Object.keys(obj).reverse()) reordered[k] = obj[k];
          return canonicalize(obj) === canonicalize(reordered);
        }
      ),
      { numRuns: 500 }
    );
  });

  it("output round-trips: parse(canonicalize(v)) canonicalizes identically", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (v) => {
        const out = canonicalize(v);
        const parsed = JSON.parse(out);
        return canonicalize(parsed) === out;
      }),
      { numRuns: 500 }
    );
  });
});
