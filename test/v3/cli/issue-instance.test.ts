import { describe, it, expect } from "vitest";
import { keygenCommand } from "../../../src/v3/cli/keygen";
import { issueInstanceCommand } from "../../../src/v3/cli/issue-instance";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";

describe("tsp issue-instance", () => {
  it("produces a signed instance package referencing the root", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "tsp-issue-"));
    const rootPath = path.join(tmp, "root.jwk");
    const instPath = path.join(tmp, "inst.jwk");

    await keygenCommand({ org: "T", domain: "t.example", out: rootPath });
    await issueInstanceCommand({
      root: rootPath,
      id: "instance-1",
      validity: "72h",
      out: instPath,
    });

    const raw = await fs.readFile(instPath, "utf-8");
    const issued = JSON.parse(raw);
    expect(issued.id).toBe("instance-1");
    expect(issued.cert.id).toBe("instance-1");
    expect(issued.cert.rootSignature).toBeDefined();
    expect(issued.privateKeyJwk.kty).toBe("OKP");

    await fs.rm(tmp, { recursive: true });
  });
});
