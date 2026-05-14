import { describe, it, expect } from "vitest";
import { keygenCommand } from "../../../src/v3/cli/keygen";
import { issueInstanceCommand } from "../../../src/v3/cli/issue-instance";
import { publishManifestCommand } from "../../../src/v3/cli/publish-manifest";
import { verifyManifestSignature } from "../../../src/v3/manifest-verify";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";

describe("tsp publish-manifest", () => {
  it("end-to-end keygen → issue → publish produces a verifiable manifest", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "tsp-pub-"));
    const rootPath = path.join(tmp, "root.jwk");
    const instDir = path.join(tmp, "instances");
    await fs.mkdir(instDir, { recursive: true });
    const inst1 = path.join(instDir, "i1.jwk");
    const manifestPath = path.join(tmp, "keys.json");

    await keygenCommand({ org: "T", domain: "t.example", out: rootPath });
    await issueInstanceCommand({ root: rootPath, id: "instance-1", validity: "72h", out: inst1 });
    await publishManifestCommand({
      root: rootPath,
      instances: path.join(instDir, "*.jwk"),
      out: manifestPath,
    });

    const manifest = JSON.parse(await fs.readFile(manifestPath, "utf-8"));
    expect(manifest.tsp).toBe("3.0");
    expect(manifest.sequence).toBe(1);
    expect(manifest.instances).toHaveLength(1);
    expect(await verifyManifestSignature(manifest)).toBe(true);

    await fs.rm(tmp, { recursive: true });
  });
});
