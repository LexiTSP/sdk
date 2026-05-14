import { verifyLocal } from "../verify";
import { verifyOnline } from "../verify-online";
import { readJson, require_ } from "./shared";
import type { TrustEnvelope } from "../types";
import type { JwkEd25519Public } from "../crypto";

export interface VerifyArgs {
  envelope?: string | boolean;
  mode?: string | boolean;
  publicKey?: string | boolean;
  json?: boolean;
}

export async function verifyCommand(args: VerifyArgs): Promise<void> {
  const envelopePath = require_("envelope", args.envelope);
  const mode = (typeof args.mode === "string" ? args.mode : "online") as "local" | "online";

  const envelope = await readJson<TrustEnvelope>(envelopePath);

  let result;
  if (mode === "local") {
    const pkPath = require_("public-key", args.publicKey);
    const publicKey = await readJson<JwkEd25519Public>(pkPath);
    result = await verifyLocal(envelope, { knownPublicKey: publicKey });
  } else {
    result = await verifyOnline(envelope);
  }

  if (args.json === true) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(result.valid ? "✓ valid" : "✗ invalid");
    for (const [name, check] of Object.entries(result.checks)) {
      if (Array.isArray(check)) {
        check.forEach((c, i) => console.log(`  ${name}[${i}]: ${c.status} — ${c.detail}`));
      } else if (check) {
        console.log(`  ${name}: ${check.status} — ${check.detail}`);
      }
    }
    if (result.warnings.length) {
      console.log("warnings:");
      result.warnings.forEach((w) => console.log(`  - ${w}`));
    }
  }

  if (!result.valid) process.exit(1);
}
