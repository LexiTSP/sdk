import { generateRootKey } from "../admin/generate-root";
import { writeJson, require_, ok, info } from "./shared";
import { sha256Hex } from "../canonical-hash";
import { canonicalize } from "../canonical";

export interface KeygenArgs {
  org?: string | boolean;
  domain?: string | boolean;
  out?: string | boolean;
}

export async function keygenCommand(args: KeygenArgs): Promise<void> {
  const org = require_("org", args.org);
  const domain = require_("domain", args.domain);
  const out = require_("out", args.out);

  const generated = await generateRootKey({ organization: org, domain });
  await writeJson(out, generated);

  const fingerprint = (await sha256Hex(canonicalize(generated.publicKeyJwk))).slice(0, 16);

  ok("Org-root generated");
  info(`organization: ${org}`);
  info(`domain:       ${domain}`);
  info(`fingerprint:  sha256:${fingerprint}…`);
  info(`written to:   ${out}`);
  console.log("");
  console.log("KEEP THIS FILE SECRET. Loss = full org compromise. Backup recommended.");
}
