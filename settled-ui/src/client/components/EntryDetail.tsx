import { useEffect, useRef } from 'react';
import { ProofViewer } from './ProofViewer.js';
import type { Entry } from '../types.js';

type Props = {
  entry:   Entry | null;
  onClose: () => void;
};

function formatTs(ns: string): string {
  const ms = Number(BigInt(ns) / 1_000_000n);
  return new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC');
}

function Field({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="space-y-0.5">
      <p className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</p>
      <p className={`text-sm text-slate-200 break-all ${mono ? 'font-mono' : ''}`}>{value}</p>
    </div>
  );
}

export function EntryDetail({ entry, onClose }: Props) {
  const panelRef = useRef<HTMLDivElement>(null);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const handleCopy = () => {
    if (entry) navigator.clipboard.writeText(JSON.stringify(entry, null, 2));
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className={`fixed inset-0 z-30 bg-black/50 transition-opacity duration-200 ${entry ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}
        onClick={onClose}
      />

      {/* Slide-in panel */}
      <div
        ref={panelRef}
        className={`fixed top-0 right-0 z-40 h-full w-full max-w-2xl bg-surface-1 border-l border-surface-3 shadow-2xl flex flex-col
          transform transition-transform duration-250 ease-out
          ${entry ? 'translate-x-0' : 'translate-x-full'}`}
      >
        {entry && (
          <>
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-3 border-b border-surface-3">
              <span className="text-sm font-semibold text-slate-200">
                Entry <span className="text-accent-blue">#{entry.seq}</span>
              </span>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleCopy}
                  className="text-xs text-slate-400 hover:text-slate-200 bg-surface-2 border border-surface-3 rounded px-2 py-1"
                >
                  Copy JSON
                </button>
                <button onClick={onClose} className="text-slate-400 hover:text-white text-lg leading-none">✕</button>
              </div>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
              <div className="grid grid-cols-2 gap-4">
                <Field label="Sequence"  value={String(entry.seq)} />
                <Field label="Timestamp" value={formatTs(entry.timestamp_ns)} mono={false} />
              </div>
              <Field label="Key"       value={entry.key}       mono={false} />
              <Field label="Data"      value={entry.data}      mono={false} />
              <Field label="Leaf Hash" value={entry.leaf_hash} />

              <div className="border-t border-surface-3 pt-4">
                <ProofViewer entry={entry} />
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
