import type { Sth, EntriesResponse, Entry, InclusionProof, ConsistencyProof } from '../types.js';

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status} ${text}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  sth(): Promise<Sth> {
    return get('/api/sth');
  },

  entries(opts: { from?: number; limit?: number; dir?: 'asc' | 'desc' }): Promise<EntriesResponse> {
    const params = new URLSearchParams();
    if (opts.from  !== undefined) params.set('from',  String(opts.from));
    if (opts.limit !== undefined) params.set('limit', String(opts.limit));
    if (opts.dir   !== undefined) params.set('dir',   opts.dir);
    return get(`/api/entries?${params}`);
  },

  entry(seq: number): Promise<Entry> {
    return get(`/api/entries/${seq}`);
  },

  proof(seq: number): Promise<InclusionProof> {
    return get(`/api/entries/${seq}/proof`);
  },

  consistency(oldSize: number, newSize: number): Promise<ConsistencyProof> {
    return get(`/api/consistency?old=${oldSize}&new=${newSize}`);
  },
};
