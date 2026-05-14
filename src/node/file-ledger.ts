/**
 * @lexitsp/sdk/node · FileLedger
 *
 * Append-only JSONL ledger persisted to disk. Node.js / Bun only.
 * Browsers should use a different storage backend (IndexedDB, etc.).
 *
 * Usage:
 *
 *   import { FileLedger } from "@lexitsp/sdk/node";
 *   const ledger = new FileLedger("./.tsp-ledger.jsonl");
 *
 *   await ledger.save(envelope);
 *   const all = await ledger.all();
 *   const result = await verifyChain(all);
 */

import fs from "node:fs/promises";
import path from "node:path";
import type { ConfidenceLevel, TrustEnvelope, TrustStats } from "../types";

export interface LedgerQuery {
  minConfidence?: number;
  maxConfidence?: number;
  maxRiskLevel?: number;
  startDate?: string;
  endDate?: string;
  source?: string;
  model?: string;
  domain?: string;
  limit?: number;
}

/**
 * Append-only file-backed ledger.
 *
 * Concurrent writes are serialized via an internal write-lock chain.
 * The on-disk format is JSONL (one envelope per line) — easy to grep,
 * stream, ship to S3, or feed into another tool.
 */
export class FileLedger {
  private entries: TrustEnvelope[] = [];
  private byId = new Map<string, TrustEnvelope>();
  private loaded = false;
  private writeLock: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  private async ensureLoaded() {
    if (this.loaded) return;
    try {
      const dir = path.dirname(path.resolve(this.filePath));
      await fs.mkdir(dir, { recursive: true }).catch((err) => {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      });
      const content = await fs.readFile(this.filePath, "utf8").catch(() => "");
      if (content) {
        for (const line of content.split("\n")) {
          if (!line.trim()) continue;
          try {
            const env = JSON.parse(line) as TrustEnvelope;
            this.entries.push(env);
            this.byId.set(env.ledger.id, env);
          } catch {
            /* skip malformed line */
          }
        }
      }
    } finally {
      this.loaded = true;
    }
  }

  async save(envelope: TrustEnvelope): Promise<void> {
    await this.ensureLoaded();
    this.writeLock = this.writeLock.then(async () => {
      this.entries.push(envelope);
      this.byId.set(envelope.ledger.id, envelope);
      await fs.appendFile(
        this.filePath,
        JSON.stringify(envelope) + "\n",
        "utf8",
      );
    });
    return this.writeLock;
  }

  async get(id: string): Promise<TrustEnvelope | null> {
    await this.ensureLoaded();
    return this.byId.get(id) ?? null;
  }

  async query(filter: LedgerQuery = {}): Promise<TrustEnvelope[]> {
    await this.ensureLoaded();
    let out = this.entries.filter((e) => {
      if (filter.minConfidence !== undefined && e.confidenceScore < filter.minConfidence) return false;
      if (filter.maxConfidence !== undefined && e.confidenceScore > filter.maxConfidence) return false;
      if (filter.maxRiskLevel !== undefined && e.alignment.riskLevel > filter.maxRiskLevel) return false;
      if (filter.startDate && e.ledger.timestamp < filter.startDate) return false;
      if (filter.endDate && e.ledger.timestamp > filter.endDate) return false;
      if (filter.source && e.source.name !== filter.source) return false;
      if (filter.model && e.process.model !== filter.model) return false;
      if (filter.domain && e.alignment.domain !== filter.domain) return false;
      return true;
    });
    if (filter.limit) out = out.slice(-filter.limit);
    return out;
  }

  async all(): Promise<TrustEnvelope[]> {
    await this.ensureLoaded();
    return [...this.entries];
  }

  async getLatest(): Promise<TrustEnvelope | null> {
    await this.ensureLoaded();
    return this.entries.length ? this.entries[this.entries.length - 1] : null;
  }

  async getLatestHash(): Promise<string | undefined> {
    const latest = await this.getLatest();
    return latest?.ledger.hash;
  }

  async count(): Promise<number> {
    await this.ensureLoaded();
    return this.entries.length;
  }

  async stats(): Promise<TrustStats> {
    await this.ensureLoaded();
    const total = this.entries.length;
    const sum = this.entries.reduce((a, e) => a + e.confidenceScore, 0);
    const levelCounts: Record<ConfidenceLevel, number> = {
      high: 0,
      medium: 0,
      low: 0,
      critical: 0,
    };
    const riskCounts: Record<string, number> = {};
    const sourceCounts = new Map<string, number>();
    const modelCounts = new Map<string, number>();
    for (const e of this.entries) {
      levelCounts[e.confidenceLevel]++;
      const r = String(e.alignment.riskLevel);
      riskCounts[r] = (riskCounts[r] ?? 0) + 1;
      sourceCounts.set(e.source.name, (sourceCounts.get(e.source.name) ?? 0) + 1);
      modelCounts.set(e.process.model, (modelCounts.get(e.process.model) ?? 0) + 1);
    }
    const topSources = [...sourceCounts.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
    const topModels = [...modelCounts.entries()]
      .map(([model, count]) => ({ model, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
    return {
      totalInteractions: total,
      averageConfidence: total ? Math.round(sum / total) : 0,
      confidenceLevelCounts: levelCounts,
      riskLevelCounts: riskCounts,
      topSources,
      topModels,
      lastHash: this.entries.length
        ? this.entries[this.entries.length - 1].ledger.hash
        : undefined,
    };
  }
}
