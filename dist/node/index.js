// src/node/file-ledger.ts
import fs from "fs/promises";
import path from "path";
var FileLedger = class {
  constructor(filePath) {
    this.filePath = filePath;
  }
  filePath;
  entries = [];
  byId = /* @__PURE__ */ new Map();
  loaded = false;
  writeLock = Promise.resolve();
  async ensureLoaded() {
    if (this.loaded) return;
    try {
      const dir = path.dirname(path.resolve(this.filePath));
      await fs.mkdir(dir, { recursive: true }).catch((err) => {
        if (err.code !== "EEXIST") throw err;
      });
      const content = await fs.readFile(this.filePath, "utf8").catch(() => "");
      if (content) {
        for (const line of content.split("\n")) {
          if (!line.trim()) continue;
          try {
            const env = JSON.parse(line);
            this.entries.push(env);
            this.byId.set(env.ledger.id, env);
          } catch {
          }
        }
      }
    } finally {
      this.loaded = true;
    }
  }
  async save(envelope) {
    await this.ensureLoaded();
    this.writeLock = this.writeLock.then(async () => {
      this.entries.push(envelope);
      this.byId.set(envelope.ledger.id, envelope);
      await fs.appendFile(
        this.filePath,
        JSON.stringify(envelope) + "\n",
        "utf8"
      );
    });
    return this.writeLock;
  }
  async get(id) {
    await this.ensureLoaded();
    return this.byId.get(id) ?? null;
  }
  async query(filter = {}) {
    await this.ensureLoaded();
    let out = this.entries.filter((e) => {
      if (filter.minConfidence !== void 0 && e.confidenceScore < filter.minConfidence) return false;
      if (filter.maxConfidence !== void 0 && e.confidenceScore > filter.maxConfidence) return false;
      if (filter.maxRiskLevel !== void 0 && e.alignment.riskLevel > filter.maxRiskLevel) return false;
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
  async all() {
    await this.ensureLoaded();
    return [...this.entries];
  }
  async getLatest() {
    await this.ensureLoaded();
    return this.entries.length ? this.entries[this.entries.length - 1] : null;
  }
  async getLatestHash() {
    const latest = await this.getLatest();
    return latest?.ledger.hash;
  }
  async count() {
    await this.ensureLoaded();
    return this.entries.length;
  }
  async stats() {
    await this.ensureLoaded();
    const total = this.entries.length;
    const sum = this.entries.reduce((a, e) => a + e.confidenceScore, 0);
    const levelCounts = {
      high: 0,
      medium: 0,
      low: 0,
      critical: 0
    };
    const riskCounts = {};
    const sourceCounts = /* @__PURE__ */ new Map();
    const modelCounts = /* @__PURE__ */ new Map();
    for (const e of this.entries) {
      levelCounts[e.confidenceLevel]++;
      const r = String(e.alignment.riskLevel);
      riskCounts[r] = (riskCounts[r] ?? 0) + 1;
      sourceCounts.set(e.source.name, (sourceCounts.get(e.source.name) ?? 0) + 1);
      modelCounts.set(e.process.model, (modelCounts.get(e.process.model) ?? 0) + 1);
    }
    const topSources = [...sourceCounts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, 5);
    const topModels = [...modelCounts.entries()].map(([model, count]) => ({ model, count })).sort((a, b) => b.count - a.count).slice(0, 5);
    return {
      totalInteractions: total,
      averageConfidence: total ? Math.round(sum / total) : 0,
      confidenceLevelCounts: levelCounts,
      riskLevelCounts: riskCounts,
      topSources,
      topModels,
      lastHash: this.entries.length ? this.entries[this.entries.length - 1].ledger.hash : void 0
    };
  }
};
export {
  FileLedger
};
