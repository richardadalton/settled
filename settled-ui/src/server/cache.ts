import { LRUCache } from 'lru-cache';

// STH cached for 60 s — matches server signing interval.
// Single entry cache; we just track expiry manually.
let sthCache: { value: object; expiresAt: number } | null = null;
const STH_TTL_MS = 60_000;

export function getCachedSth(): object | null {
  if (sthCache && Date.now() < sthCache.expiresAt) return sthCache.value;
  return null;
}

export function setCachedSth(value: object): void {
  sthCache = { value, expiresAt: Date.now() + STH_TTL_MS };
}

// Entry cache: immutable once written, so no TTL needed.
export const entryCache = new LRUCache<string, object>({ max: 5_000 });

// Proof cache: deterministic for (seq, tree_size), keyed as "seq:tree_size".
export const proofCache = new LRUCache<string, object>({ max: 1_000 });
