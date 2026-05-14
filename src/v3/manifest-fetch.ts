/**
 * @lexitsp/sdk v3 · manifest fetch
 *
 * In-memory LRU + ETag conditional revalidation.
 */

import type { TrustManifest } from "./manifest-types";

const DEFAULT_TTL_MS = 60 * 60 * 1000;
const DEFAULT_MAX_ENTRIES = 100;

interface CacheEntry {
  manifest: TrustManifest;
  fetchedAt: number;
  etag?: string;
}

const cache = new Map<string, CacheEntry>();

export function clearManifestCache(): void {
  cache.clear();
}

export interface FetchManifestOptions {
  fetch?: typeof globalThis.fetch;
  ttlMs?: number;
  maxEntries?: number;
}

export interface FetchManifestResult {
  manifest: TrustManifest;
  etag?: string;
  fromCache: boolean;
  revalidated: boolean;
  fetchedAt: number;
}

function evictIfNeeded(maxEntries: number): void {
  if (cache.size <= maxEntries) return;
  const entries = Array.from(cache.entries()).sort((a, b) => a[1].fetchedAt - b[1].fetchedAt);
  const toRemove = entries.length - maxEntries;
  for (let i = 0; i < toRemove; i++) cache.delete(entries[i][0]);
}

export async function fetchManifest(
  url: string,
  opts: FetchManifestOptions = {}
): Promise<FetchManifestResult> {
  const fetchFn = opts.fetch ?? globalThis.fetch;
  const ttl = opts.ttlMs ?? DEFAULT_TTL_MS;
  const maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const now = Date.now();

  const cached = cache.get(url);

  if (cached && now - cached.fetchedAt < ttl) {
    return {
      manifest: cached.manifest,
      etag: cached.etag,
      fromCache: true,
      revalidated: false,
      fetchedAt: cached.fetchedAt,
    };
  }

  const headers: Record<string, string> = { Accept: "application/json" };
  if (cached?.etag) headers["If-None-Match"] = cached.etag;

  const response = await fetchFn(url, { headers });

  if (response.status === 304 && cached) {
    cached.fetchedAt = now;
    cache.set(url, cached);
    return {
      manifest: cached.manifest,
      etag: cached.etag,
      fromCache: true,
      revalidated: true,
      fetchedAt: now,
    };
  }

  if (response.status < 200 || response.status >= 300) {
    throw new Error(`fetchManifest: unexpected status ${response.status} for ${url}`);
  }

  const manifest = (await response.json()) as TrustManifest;
  const etag = response.headers.get("etag") ?? undefined;
  const entry: CacheEntry = { manifest, fetchedAt: now, etag };
  cache.set(url, entry);
  evictIfNeeded(maxEntries);

  return { manifest, etag, fromCache: false, revalidated: false, fetchedAt: now };
}
