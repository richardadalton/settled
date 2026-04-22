import { useState } from 'react';
import { clsx } from 'clsx';

export type Filters = {
  key:     string;
  data:    string;
  fromSeq: string;
  toSeq:   string;
};

type Props = {
  filters:    Filters;
  onChange:   (f: Filters) => void;
  treeSize:   number;
  onSeek:     (seq: number) => void;
  onJumpFirst:   () => void;
  onJumpLatest:  () => void;
};

function Chip({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 bg-accent-blue/10 text-accent-blue border border-accent-blue/20 rounded px-2 py-0.5 text-xs">
      {label}
      <button onClick={onRemove} className="hover:text-white">✕</button>
    </span>
  );
}

export function FilterBar({ filters, onChange, treeSize, onSeek, onJumpFirst, onJumpLatest }: Props) {
  const [seekInput, setSeekInput] = useState('');

  const set = (k: keyof Filters) => (e: React.ChangeEvent<HTMLInputElement>) =>
    onChange({ ...filters, [k]: e.target.value });

  const activeFilters: { label: string; clear: () => void }[] = [];
  if (filters.key)     activeFilters.push({ label: `key: ${filters.key}`,       clear: () => onChange({ ...filters, key: '' }) });
  if (filters.data)    activeFilters.push({ label: `data: ${filters.data}`,     clear: () => onChange({ ...filters, data: '' }) });
  if (filters.fromSeq) activeFilters.push({ label: `from seq ${filters.fromSeq}`, clear: () => onChange({ ...filters, fromSeq: '' }) });
  if (filters.toSeq)   activeFilters.push({ label: `to seq ${filters.toSeq}`,   clear: () => onChange({ ...filters, toSeq: '' }) });

  return (
    <div className="bg-surface-1 border-b border-surface-3 px-4 py-2 space-y-2">
      <div className="flex flex-wrap gap-2 items-center">
        {/* Seek */}
        <div className="flex items-center gap-1">
          <input
            type="number"
            min={0}
            max={Math.max(0, treeSize - 1)}
            placeholder="Go to seq…"
            value={seekInput}
            onChange={e => setSeekInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && seekInput !== '') {
                onSeek(Number(seekInput));
                setSeekInput('');
              }
            }}
            className="w-32 bg-surface-2 border border-surface-3 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
          />
          <button
            onClick={() => { if (seekInput !== '') { onSeek(Number(seekInput)); setSeekInput(''); } }}
            className="bg-surface-2 hover:bg-surface-3 border border-surface-3 rounded px-2 py-1 text-xs text-slate-300"
          >
            Seek
          </button>
        </div>

        <button onClick={onJumpFirst}  className="bg-surface-2 hover:bg-surface-3 border border-surface-3 rounded px-2 py-1 text-xs text-slate-300">⏮ First</button>
        <button onClick={onJumpLatest} className="bg-surface-2 hover:bg-surface-3 border border-surface-3 rounded px-2 py-1 text-xs text-slate-300">⏭ Latest</button>

        <span className="text-surface-3">│</span>

        {/* Filters */}
        <input
          placeholder="Filter by key…"
          value={filters.key}
          onChange={set('key')}
          className="w-36 bg-surface-2 border border-surface-3 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
        />
        <input
          placeholder="Filter by data…"
          value={filters.data}
          onChange={set('data')}
          className="w-40 bg-surface-2 border border-surface-3 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
        />
        <input
          type="number"
          placeholder="From seq"
          value={filters.fromSeq}
          onChange={set('fromSeq')}
          className="w-24 bg-surface-2 border border-surface-3 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
        />
        <input
          type="number"
          placeholder="To seq"
          value={filters.toSeq}
          onChange={set('toSeq')}
          className="w-24 bg-surface-2 border border-surface-3 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
        />
      </div>

      {activeFilters.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {activeFilters.map(f => <Chip key={f.label} label={f.label} onRemove={f.clear} />)}
          <button
            onClick={() => onChange({ key: '', data: '', fromSeq: '', toSeq: '' })}
            className="text-xs text-slate-500 hover:text-slate-300 underline"
          >
            Clear all
          </button>
        </div>
      )}
    </div>
  );
}
