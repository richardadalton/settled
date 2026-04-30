import { useState } from 'react';
import { clsx } from 'clsx';
import { Badge } from './Badge.js';
import type { SthState } from '../hooks/useSth.js';

type Props = { state: SthState };

function formatTs(ns: string): string {
  const ms = Number(BigInt(ns) / 1_000_000n);
  return new Date(ms).toLocaleString();
}

export function SthHeader({ state }: Props) {
  const { sth, status, error } = state;
  const [showKey, setShowKey] = useState(false);

  return (
    <div className="sticky top-0 z-20 bg-surface-1 border-b border-surface-3 px-4 py-2 flex items-center gap-4 flex-wrap text-xs">
      <span className="text-slate-400 font-semibold tracking-widest uppercase">Settled</span>

      {sth ? (
        <>
          <span className="text-slate-300">
            Tree size: <span className="text-accent-blue font-semibold">{sth.tree_size.toLocaleString()}</span>
          </span>
          <span className="text-slate-300">
            Signed: <span className="text-slate-200">{formatTs(sth.timestamp_ns)}</span>
          </span>
          <span className="text-slate-300">
            Root: <span className="text-slate-400 font-mono">{sth.root_hash.slice(0, 16)}…</span>
          </span>
          <button
            onClick={() => setShowKey(v => !v)}
            className="text-slate-400 hover:text-slate-200 underline underline-offset-2"
            title={sth.public_key}
          >
            Key v{sth.key_version}: {showKey ? sth.public_key : `${sth.public_key.slice(0, 12)}…`}
          </button>
        </>
      ) : (
        <span className="text-slate-500">Loading…</span>
      )}

      <div className="ml-auto flex items-center gap-2">
        {error && (
          <span className="text-accent-red text-[11px]" title={error}>
            {error.slice(0, 60)}
          </span>
        )}
        <Badge status={status} />
      </div>
    </div>
  );
}
