import { useState, useCallback, useRef } from 'react';
import { api } from '../lib/api.js';
import type { Entry } from '../types.js';

const PAGE = 100;

type KeyMode =
  | { active: false }
  | { active: true; key: string; nextCursor: string };

export type EntriesState = {
  entries:   Entry[];
  treeSize:  number;
  loading:   boolean;
  error:     string | null;
  hasOlder:  boolean;
  hasNewer:  boolean;
  isKeyMode: boolean;
};

export type EntriesActions = {
  seekTo:      (seq: number) => void;
  loadOlder:   () => void;
  loadNewer:   () => void;
  jumpLatest:  () => void;
  jumpFirst:   () => void;
  appendLive:  (entry: Entry) => void;
  setTreeSize: (n: number) => void;
  loadByKey:   (key: string) => void;
};

export function useEntries(): [EntriesState, EntriesActions] {
  const [entries, setEntries]   = useState<Entry[]>([]);
  const [treeSize, setTreeSize] = useState(0);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);

  // Track the range of seqs currently loaded
  const minSeq = useRef<number | null>(null);
  const maxSeq = useRef<number | null>(null);
  const keyMode = useRef<KeyMode>({ active: false });

  const hasOlder = !keyMode.current.active && minSeq.current !== null && minSeq.current > 0;
  const hasNewer = keyMode.current.active
    ? keyMode.current.nextCursor !== '0'
    : maxSeq.current !== null && treeSize > 0 && maxSeq.current < treeSize - 1;
  const isKeyMode = keyMode.current.active;

  const load = useCallback(async (from: number, dir: 'asc' | 'desc', replace: boolean) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.entries({ from, limit: PAGE, dir });
      setTreeSize(res.tree_size);
      if (res.entries.length === 0) return;

      setEntries(prev => {
        const merged = replace
          ? res.entries
          : dir === 'asc'
            ? [...prev, ...res.entries.filter(e => e.seq > (maxSeq.current ?? -1))]
            : [...res.entries.filter(e => e.seq < (minSeq.current ?? Infinity)), ...prev];
        // Deduplicate and sort
        const unique = Array.from(new Map(merged.map(e => [e.seq, e])).values())
          .sort((a, b) => a.seq - b.seq);
        minSeq.current = unique[0]?.seq ?? null;
        maxSeq.current = unique[unique.length - 1]?.seq ?? null;
        return unique;
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const seekTo = useCallback((seq: number) => {
    keyMode.current = { active: false };
    minSeq.current = null;
    maxSeq.current = null;
    const from = Math.max(0, seq - Math.floor(PAGE / 2));
    load(from, 'asc', true);
  }, [load]);

  const loadOlder = useCallback(() => {
    if (keyMode.current.active) return;
    if (minSeq.current === null || minSeq.current === 0) return;
    const from = Math.max(0, minSeq.current - PAGE);
    load(from, 'asc', false);
  }, [load]);

  const loadNewer = useCallback(() => {
    if (keyMode.current.active) {
      const km = keyMode.current;
      if (km.nextCursor === '0') return;
      setLoading(true);
      setError(null);
      api.entriesByKey(km.key, km.nextCursor).then(res => {
        keyMode.current = { active: true, key: km.key, nextCursor: res.next_cursor };
        setEntries(prev => {
          const merged = [...prev, ...res.entries];
          return Array.from(new Map(merged.map(e => [e.seq, e])).values())
            .sort((a, b) => a.seq - b.seq);
        });
      }).catch(e => setError(String(e))).finally(() => setLoading(false));
      return;
    }
    if (maxSeq.current === null) return;
    load(maxSeq.current + 1, 'asc', false);
  }, [load]);

  const jumpLatest = useCallback(() => {
    keyMode.current = { active: false };
    minSeq.current = null;
    maxSeq.current = null;
    api.sth().then(sth => {
      const from = Math.max(0, sth.tree_size - PAGE);
      setTreeSize(sth.tree_size);
      load(from, 'asc', true);
    });
  }, [load]);

  const jumpFirst = useCallback(() => {
    keyMode.current = { active: false };
    minSeq.current = null;
    maxSeq.current = null;
    load(0, 'asc', true);
  }, [load]);

  const appendLive = useCallback((entry: Entry) => {
    if (keyMode.current.active) return;
    setEntries(prev => {
      if (prev.some(e => e.seq === entry.seq)) return prev;
      const next = [...prev, entry].sort((a, b) => a.seq - b.seq);
      minSeq.current = next[0]?.seq ?? null;
      maxSeq.current = next[next.length - 1]?.seq ?? null;
      return next;
    });
    setTreeSize(t => Math.max(t, entry.seq + 1));
  }, []);

  const loadByKey = useCallback((key: string) => {
    keyMode.current = { active: true, key, nextCursor: '0' };
    minSeq.current = null;
    maxSeq.current = null;
    setLoading(true);
    setError(null);
    setEntries([]);
    api.entriesByKey(key, '0').then(res => {
      keyMode.current = { active: true, key, nextCursor: res.next_cursor };
      setEntries(res.entries);
    }).catch(e => setError(String(e))).finally(() => setLoading(false));
  }, []);

  return [
    { entries, treeSize, loading, error, hasOlder, hasNewer, isKeyMode },
    { seekTo, loadOlder, loadNewer, jumpLatest, jumpFirst, appendLive, setTreeSize, loadByKey },
  ];
}
