import { promises as fs } from "node:fs";
import path from "node:path";
import { buildManifest } from "../admin/build-manifest";
import { readJson, writeJson, require_, ok, info, parseDuration } from "./shared";
import type { GeneratedRootKey } from "../admin/generate-root";
import type { IssuedInstance } from "../admin/issue-instance";
import type { TrustManifest, RevokedEntry } from "../manifest-types";

export interface PublishManifestArgs {
  root?: string | boolean;
  instances?: string | boolean;
  revoked?: string | boolean;
  previous?: string | boolean;
  acceptableAge?: string | boolean;
  out?: string | boolean;
}

async function expandGlob(pattern: string): Promise<string[]> {
  const m = /^(.*)\*([^*]*)$/.exec(pattern);
  if (!m) return [pattern];
  const prefix = m[1];
  const suffix = m[2];
  const dir = prefix.endsWith("/") || prefix.endsWith("\\") ? prefix.replace(/[\\/]$/, "") : path.dirname(prefix);
  const filePrefix = prefix.endsWith("/") || prefix.endsWith("\\") ? "" : path.basename(prefix);
  const entries = await fs.readdir(dir);
  return entries
    .filter((e) => e.startsWith(filePrefix) && e.endsWith(suffix))
    .map((e) => path.join(dir, e));
}

export async function publishManifestCommand(args: PublishManifestArgs): Promise<void> {
  const rootPath = require_("root", args.root);
  const instancesPattern = require_("instances", args.instances);
  const out = require_("out", args.out);

  const rootPackage = await readJson<GeneratedRootKey>(rootPath);
  const instancePaths = await expandGlob(instancesPattern);
  const instances = await Promise.all(instancePaths.map((p) => readJson<IssuedInstance>(p)));

  const revoked: RevokedEntry[] =
    args.revoked && typeof args.revoked === "string" ? await readJson<RevokedEntry[]>(args.revoked) : [];

  let previousSequence: number | undefined;
  if (args.previous && typeof args.previous === "string") {
    const prev = await readJson<TrustManifest>(args.previous);
    previousSequence = prev.sequence;
  }

  const acceptableAgeSeconds =
    args.acceptableAge && typeof args.acceptableAge === "string"
      ? Math.floor(parseDuration(args.acceptableAge) / 1000)
      : 86400;

  const manifest = await buildManifest({
    rootPackage,
    instances,
    revoked,
    previousSequence,
    acceptableAgeSeconds,
  });

  await writeJson(out, manifest);

  ok("Manifest published");
  info(`organization: ${manifest.organization.name} (${manifest.organization.domain})`);
  info(`sequence:     ${manifest.sequence}`);
  info(`issuedAt:     ${manifest.issuedAt}`);
  info(`instances:    ${manifest.instances.length}`);
  info(`revoked:      ${manifest.revoked.length}`);
  info(`written to:   ${out}`);
}
