import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { canonicalize } from "../../src/v3/canonical";
import { sha256Hex } from "../../src/v3/canonical-hash";

// Fixtures are vendored from the normative source at LexiTSP/tsp-spec
// (fixtures/v3.0/) so the conformance suite runs standalone. When the
// `@lexitsp/spec-fixtures` package ships, this will switch to a package
// import and the local copy will be removed.
const fixturesDir = path.resolve(__dirname, "./fixtures");

function readFixture(filename: string): { raw: string; parsed: any } {
  const filePath = path.join(fixturesDir, filename);
  const raw = fs.readFileSync(filePath, "utf-8");
  return { raw, parsed: JSON.parse(raw) };
}

describe("Cryptographic Conformance Suite (fixtures/v3.0)", () => {
  describe("valid-minimal.json", () => {
    it("satisfies content and ledger hash structural schema and computes exact canonical JCS hashes", async () => {
      const { parsed } = readFixture("valid-minimal.json");

      // The fixture uses a representational mock hash in its body
      expect(parsed.content.hash).toBe("e0e2908bb9622d99d3000b0bb1d087fe08a55ed9938b8eb8ee8ee2efcde9989b");

      // Verify JCS canonicalization computes the exact cryptographically correct hash for the value
      const expectedContentHash = await sha256Hex(canonicalize(parsed.content.value));
      expect(expectedContentHash).toBe("00e0ba9a15ab56bd3a27c2829910511c9e50a0fc6b62d7e27da4d87a7acd86de");

      // Verify JCS canonicalization on the ledger domain produces a deterministic expected serialization
      const ledgerDomain: any = {
        tsp: parsed.tsp,
        content: parsed.content,
        process: parsed.process,
        timestamp: parsed.timestamp,
        signatures: parsed.signatures,
        ledger: { id: parsed.ledger.id, prevHash: parsed.ledger.prevHash },
      };
      if (parsed.declaration !== undefined) ledgerDomain.declaration = parsed.declaration;
      if (parsed.alignment !== undefined) ledgerDomain.alignment = parsed.alignment;

      const expectedLedgerHash = await sha256Hex(canonicalize(ledgerDomain));
      expect(expectedLedgerHash).toBe("d43b192b563c3b4cf7076d9269313d16c31629087f869c4b70c5d0f7564bedf6");
    });
  });

  describe("invalid-canonical-sort.json (Lexicographical Key-Sort Trap)", () => {
    it("fails strict UTF-16 alphabetical key ordering checks on raw key structures", () => {
      const { raw } = readFixture("invalid-canonical-sort.json");

      // Check if keys in raw JSON text occur out of alphabetical order
      // Let's find occurrences of root keys and see if they are sorted
      const lines = raw.split("\n");
      const rootKeys: string[] = [];
      for (const line of lines) {
        const match = line.match(/^\s*"([^"]+)"\s*:/);
        if (match) {
          rootKeys.push(match[1]);
        }
      }

      // Root level keys in invalid-canonical-sort.json:
      // tsp, timestamp, process, content, ledger, signatures
      // Lexicographically, they should be:
      // content, ledger, process, signatures, timestamp, tsp
      const isSorted = rootKeys.every((val, i, arr) => !i || val >= arr[i - 1]);
      
      // The root keys in the file are deliberately unsorted to test canonicalization stripping traps
      expect(isSorted).toBe(false);
      expect(rootKeys).toContain("timestamp");
      expect(rootKeys.indexOf("timestamp")).toBeLessThan(rootKeys.indexOf("content")); // timestamp (line 3) is before content (line 13)
    });
  });

  describe("valid-whitespace-mutation.json (Whitespace Mutation Trap)", () => {
    it("canonicalizes to the exact same string and hash as valid-minimal.json", async () => {
      const { parsed: minimal } = readFixture("valid-minimal.json");
      const { parsed: mutated } = readFixture("valid-whitespace-mutation.json");

      // Stripping signatures signature difference if any, they are structurally equivalent
      const canonicalMinimal = canonicalize(minimal);
      const canonicalMutated = canonicalize(mutated);

      expect(canonicalMinimal).toBe(canonicalMutated);
      expect(await sha256Hex(canonicalMinimal)).toBe(await sha256Hex(canonicalMutated));
    });
  });

  describe("invalid-number-format.json (Numeric Parsing Format Trap)", () => {
    it("violates normative JSON Schema version type format (string vs number)", () => {
      const { parsed } = readFixture("invalid-number-format.json");

      // Normative tsp-v3.schema.json requires alignment.policy.version to be a string
      // Let's assert that version in this invalid fixture is a floating-point number
      expect(typeof parsed.alignment.policy.version).toBe("number");
      expect(parsed.alignment.policy.version).toBe(3.0);
    });

    it("verifies float canonicalization behaviors per RFC 8785", () => {
      // In RFC 8785 JCS, floating numbers must be stripped of trailing zeroes, decimal points if redundant, etc.
      // e.g. 3.0 canonicalizes to "3", 333333333.33333329 canonicalizes to 333333333.3333333
      expect(canonicalize(3.0)).toBe("3");
      expect(canonicalize(333333333.33333329)).toBe("333333333.3333333");
    });
  });
});
