import { describe, it, expect } from "vitest";
import { keygenCommand } from "../../../src/v3/cli/keygen";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";

describe("tsp keygen", () => {
  it("writes a valid root key file", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "tsp-keygen-"));
    const outPath = path.join(tmpDir, "root.jwk");

    await keygenCommand({ org: "TestOrg", domain: "test.example", out: outPath });

    const raw = await fs.readFile(outPath, "utf-8");
    const parsed = JSON.parse(raw);
    expect(parsed.organization).toBe("TestOrg");
    expect(parsed.domain).toBe("test.example");
    expect(parsed.privateKeyJwk.kty).toBe("OKP");
    expect(parsed.privateKeyJwk.crv).toBe("Ed25519");
    expect(parsed.privateKeyJwk.d).toBeDefined();
    expect(parsed.publicKeyJwk.x).toBeDefined();

    await fs.rm(tmpDir, { recursive: true });
  });
});
