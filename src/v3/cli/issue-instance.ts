import { issueInstance } from "../admin/issue-instance";
import { readJson, writeJson, require_, ok, info, parseDuration } from "./shared";
import type { GeneratedRootKey } from "../admin/generate-root";

export interface IssueInstanceArgs {
  root?: string | boolean;
  id?: string | boolean;
  validity?: string | boolean;
  out?: string | boolean;
}

export async function issueInstanceCommand(args: IssueInstanceArgs): Promise<void> {
  const rootPath = require_("root", args.root);
  const id = require_("id", args.id);
  const validity = require_("validity", args.validity);
  const out = require_("out", args.out);

  const rootPackage = await readJson<GeneratedRootKey>(rootPath);
  const validityMs = parseDuration(validity);
  const validFrom = new Date();
  const validUntil = new Date(validFrom.getTime() + validityMs);

  const issued = await issueInstance({
    rootPackage,
    instanceId: id,
    validFrom,
    validUntil,
  });

  await writeJson(out, issued);

  ok("Instance issued");
  info(`id:           ${id}`);
  info(`validFrom:    ${validFrom.toISOString()}`);
  info(`validUntil:   ${validUntil.toISOString()}`);
  info(`written to:   ${out}`);
}
