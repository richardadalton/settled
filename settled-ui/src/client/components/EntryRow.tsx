import { clsx } from 'clsx';
import type { Entry } from '../types.js';

type Props = {
  entry:    Entry;
  selected: boolean;
  onClick:  () => void;
  style:    React.CSSProperties;
};

function formatTs(ns: string): string {
  const ms = Number(BigInt(ns) / 1_000_000n);
  return new Date(ms).toLocaleTimeString(undefined, { hour12: false });
}

function truncate(s: string, n: number) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

export function EntryRow({ entry, selected, onClick, style }: Props) {
  return (
    <div
      style={style}
      onClick={onClick}
      className={clsx(
        'absolute left-0 right-0 flex items-center gap-0 border-b border-surface-2 cursor-pointer select-none transition-colors',
        selected ? 'bg-accent-blue/10' : 'hover:bg-surface-2',
      )}
    >
      <Cell w="w-20"  dim>{entry.seq}</Cell>
      <Cell w="w-36">{truncate(entry.key,  32)}</Cell>
      <Cell w="flex-1">{truncate(entry.data, 80)}</Cell>
      <Cell w="w-28"  dim>{formatTs(entry.timestamp_ns)}</Cell>
      <Cell w="w-32"  dim>{entry.leaf_hash.slice(0, 12)}…</Cell>
    </div>
  );
}

function Cell({ children, w, dim }: { children: React.ReactNode; w: string; dim?: boolean }) {
  return (
    <div className={clsx('px-3 py-2 text-xs truncate', w, dim ? 'text-slate-500' : 'text-slate-200')}>
      {children}
    </div>
  );
}
