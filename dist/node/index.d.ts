import { TrustEnvelope, TrustStats } from '../types.js';

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

interface LedgerQuery {
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
declare class FileLedger {
    private readonly filePath;
    private entries;
    private byId;
    private loaded;
    private writeLock;
    constructor(filePath: string);
    private ensureLoaded;
    save(envelope: TrustEnvelope): Promise<void>;
    get(id: string): Promise<TrustEnvelope | null>;
    query(filter?: LedgerQuery): Promise<TrustEnvelope[]>;
    all(): Promise<TrustEnvelope[]>;
    getLatest(): Promise<TrustEnvelope | null>;
    getLatestHash(): Promise<string | undefined>;
    count(): Promise<number>;
    stats(): Promise<TrustStats>;
}

export { FileLedger, type LedgerQuery };
