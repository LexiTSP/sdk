import { keygenCommand } from "./keygen";
import { issueInstanceCommand } from "./issue-instance";
import { publishManifestCommand } from "./publish-manifest";
import { verifyCommand } from "./verify";

function parseFlags(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      out[key] = true;
    } else {
      out[key] = next;
      i++;
    }
  }
  return out;
}

const HELP = `tsp — Trust Standard Protocol CLI

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

export async function main(argv: string[]): Promise<void> {
  const [, , cmd, ...rest] = argv;
  if (!cmd || cmd === "--help" || cmd === "-h") {
    console.log(HELP);
    return;
  }

  const flags = parseFlags(rest);
  const camel = (s: string): string => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  const args: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(flags)) args[camel(k)] = v;

  try {
    if (cmd === "keygen") await keygenCommand(args as never);
    else if (cmd === "issue-instance") await issueInstanceCommand(args as never);
    else if (cmd === "publish-manifest") await publishManifestCommand(args as never);
    else if (cmd === "verify") await verifyCommand(args as never);
    else {
      console.error(`Unknown command: ${cmd}`);
      console.log(HELP);
      process.exit(2);
    }
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    process.exit(1);
  }
}
