import { promises as fs } from "node:fs";
import path from "node:path";

export async function writeJson(filePath: string, data: unknown): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
}

export async function readJson<T>(filePath: string): Promise<T> {
  const raw = await fs.readFile(filePath, "utf-8");
  return JSON.parse(raw) as T;
}

export function require_(name: string, value: string | undefined | boolean): string {
  if (typeof value !== "string" || !value) {
    console.error(`Missing required flag: --${name}`);
    process.exit(2);
  }
  return value;
}

export function ok(msg: string): void {
  console.log(`✓ ${msg}`);
}

export function info(msg: string): void {
  console.log(`  ${msg}`);
}

export function parseDuration(input: string): number {
  const m = /^(\d+)([hdm])$/.exec(input);
  if (!m) throw new Error(`Cannot parse duration: ${input}. Use e.g. "72h", "30d", "15m".`);
  const n = parseInt(m[1], 10);
  const unit = m[2];
  if (unit === "h") return n * 3600 * 1000;
  if (unit === "d") return n * 86400 * 1000;
  if (unit === "m") return n * 60 * 1000;
  throw new Error(`unreachable`);
}
