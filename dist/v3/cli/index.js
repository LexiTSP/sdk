import {
  sha256Hex,
  verifyLocal,
  verifyOnline
} from "../../chunk-SWH3RRGF.js";
import {
  buildManifest,
  generateRootKey,
  issueInstance
} from "../../chunk-ALIGHPKW.js";
import {
  canonicalize
} from "../../chunk-CCJVYHGK.js";

// src/v3/cli/shared.ts
import { promises as fs } from "fs";
import path from "path";
async function writeJson(filePath, data) {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
}
async function readJson(filePath) {
  const raw = await fs.readFile(filePath, "utf-8");
  return JSON.parse(raw);
}
function require_(name, value) {
  if (typeof value !== "string" || !value) {
    console.error(`Missing required flag: --${name}`);
    process.exit(2);
  }
  return value;
}
function ok(msg) {
  console.log(`\u2713 ${msg}`);
}
function info(msg) {
  console.log(`  ${msg}`);
}
function parseDuration(input) {
  const m = /^(\d+)([hdm])$/.exec(input);
  if (!m) throw new Error(`Cannot parse duration: ${input}. Use e.g. "72h", "30d", "15m".`);
  const n = parseInt(m[1], 10);
  const unit = m[2];
  if (unit === "h") return n * 3600 * 1e3;
  if (unit === "d") return n * 86400 * 1e3;
  if (unit === "m") return n * 60 * 1e3;
  throw new Error(`unreachable`);
}

// src/v3/cli/keygen.ts
async function keygenCommand(args) {
  const org = require_("org", args.org);
  const domain = require_("domain", args.domain);
  const out = require_("out", args.out);
  const generated = await generateRootKey({ organization: org, domain });
  await writeJson(out, generated);
  const fingerprint = (await sha256Hex(canonicalize(generated.publicKeyJwk))).slice(0, 16);
  ok("Org-root generated");
  info(`organization: ${org}`);
  info(`domain:       ${domain}`);
  info(`fingerprint:  sha256:${fingerprint}\u2026`);
  info(`written to:   ${out}`);
  console.log("");
  console.log("KEEP THIS FILE SECRET. Loss = full org compromise. Backup recommended.");
}

// src/v3/cli/issue-instance.ts
async function issueInstanceCommand(args) {
  const rootPath = require_("root", args.root);
  const id = require_("id", args.id);
  const validity = require_("validity", args.validity);
  const out = require_("out", args.out);
  const rootPackage = await readJson(rootPath);
  const validityMs = parseDuration(validity);
  const validFrom = /* @__PURE__ */ new Date();
  const validUntil = new Date(validFrom.getTime() + validityMs);
  const issued = await issueInstance({
    rootPackage,
    instanceId: id,
    validFrom,
    validUntil
  });
  await writeJson(out, issued);
  ok("Instance issued");
  info(`id:           ${id}`);
  info(`validFrom:    ${validFrom.toISOString()}`);
  info(`validUntil:   ${validUntil.toISOString()}`);
  info(`written to:   ${out}`);
}

// src/v3/cli/publish-manifest.ts
import { promises as fs2 } from "fs";
import path2 from "path";
async function expandGlob(pattern) {
  const m = /^(.*)\*([^*]*)$/.exec(pattern);
  if (!m) return [pattern];
  const prefix = m[1];
  const suffix = m[2];
  const dir = prefix.endsWith("/") || prefix.endsWith("\\") ? prefix.replace(/[\\/]$/, "") : path2.dirname(prefix);
  const filePrefix = prefix.endsWith("/") || prefix.endsWith("\\") ? "" : path2.basename(prefix);
  const entries = await fs2.readdir(dir);
  return entries.filter((e) => e.startsWith(filePrefix) && e.endsWith(suffix)).map((e) => path2.join(dir, e));
}
async function publishManifestCommand(args) {
  const rootPath = require_("root", args.root);
  const instancesPattern = require_("instances", args.instances);
  const out = require_("out", args.out);
  const rootPackage = await readJson(rootPath);
  const instancePaths = await expandGlob(instancesPattern);
  const instances = await Promise.all(instancePaths.map((p) => readJson(p)));
  const revoked = args.revoked && typeof args.revoked === "string" ? await readJson(args.revoked) : [];
  let previousSequence;
  if (args.previous && typeof args.previous === "string") {
    const prev = await readJson(args.previous);
    previousSequence = prev.sequence;
  }
  const acceptableAgeSeconds = args.acceptableAge && typeof args.acceptableAge === "string" ? Math.floor(parseDuration(args.acceptableAge) / 1e3) : 86400;
  const manifest = await buildManifest({
    rootPackage,
    instances,
    revoked,
    previousSequence,
    acceptableAgeSeconds
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

// src/v3/cli/verify.ts
async function verifyCommand(args) {
  const envelopePath = require_("envelope", args.envelope);
  const mode = typeof args.mode === "string" ? args.mode : "online";
  const envelope = await readJson(envelopePath);
  let result;
  if (mode === "local") {
    const pkPath = require_("public-key", args.publicKey);
    const publicKey = await readJson(pkPath);
    result = await verifyLocal(envelope, { knownPublicKey: publicKey });
  } else {
    result = await verifyOnline(envelope);
  }
  if (args.json === true) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(result.valid ? "\u2713 valid" : "\u2717 invalid");
    for (const [name, check] of Object.entries(result.checks)) {
      if (Array.isArray(check)) {
        check.forEach((c, i) => console.log(`  ${name}[${i}]: ${c.status} \u2014 ${c.detail}`));
      } else if (check) {
        console.log(`  ${name}: ${check.status} \u2014 ${check.detail}`);
      }
    }
    if (result.warnings.length) {
      console.log("warnings:");
      result.warnings.forEach((w) => console.log(`  - ${w}`));
    }
  }
  if (!result.valid) process.exit(1);
}

// src/v3/cli/index.ts
function parseFlags(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === void 0 || next.startsWith("--")) {
      out[key] = true;
    } else {
      out[key] = next;
      i++;
    }
  }
  return out;
}
var HELP = `tsp \u2014 Trust Standard Protocol CLI

Usage: tsp <command> [flags]

Commands:
  keygen            Generate org-root keypair
                    Flags: --org <name> --domain <hostname> --out <path>

  issue-instance    Issue a signed instance certificate
                    Flags: --root <path> --id <string> --validity <duration> --out <path>

  publish-manifest  Build and sign a TrustManifest
                    Flags: --root <path> --instances <glob> --out <path>
                           [--revoked <path>] [--previous <path>] [--acceptable-age <duration>]

  verify            Verify an envelope (online or local)
                    Flags: --envelope <path> [--mode local|online] [--public-key <path>] [--json]
`;
async function main(argv) {
  const [, , cmd, ...rest] = argv;
  if (!cmd || cmd === "--help" || cmd === "-h") {
    console.log(HELP);
    return;
  }
  const flags = parseFlags(rest);
  const camel = (s) => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  const args = {};
  for (const [k, v] of Object.entries(flags)) args[camel(k)] = v;
  try {
    if (cmd === "keygen") await keygenCommand(args);
    else if (cmd === "issue-instance") await issueInstanceCommand(args);
    else if (cmd === "publish-manifest") await publishManifestCommand(args);
    else if (cmd === "verify") await verifyCommand(args);
    else {
      console.error(`Unknown command: ${cmd}`);
      console.log(HELP);
      process.exit(2);
    }
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
}
export {
  main
};
