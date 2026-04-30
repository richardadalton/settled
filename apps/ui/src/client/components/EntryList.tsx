import { useRef, useEffect, useCallback, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { clsx } from 'clsx';
import { EntryRow } from './EntryRow.js';
import type { Entry } from '../types.js';
import type { EntriesState, EntriesActions } from '../hooks/useEntries.js';

const ROW_H = 36;

type Props = {
  state:       EntriesState;
  actions:     EntriesActions;
  filters:     { key: string; data: string; fromSeq: string; toSeq: string };
  liveTail:    boolean;
  onPause:     () => void;
  onSelect:    (e: Entry) => void;
  selected:    Entry | null;
  connected:   boolean;
};

function applyFilters(entries: Entry[], f: Props['filters']): Entry[] {
  return entries.filter(e => {
    if (f.key  && !e.key.toLowerCase().includes(f.key.toLowerCase()))   return false;
    if (f.data && !e.data.toLowerCase().includes(f.data.toLowerCase())) return false;
    if (f.fromSeq && e.seq < Number(f.fromSeq)) return false;
    if (f.toSeq   && e.seq > Number(f.toSeq))   return false;
    return true;
  });
}

export function EntryList({ state, actions, filters, liveTail, onPause, onSelect, selected, connected }: Props) {
  const { entries, loading, error, hasOlder, hasNewer } = state;
  const parentRef = useRef<HTMLDivElement>(null);
  const [pendingCount, setPendingCount] = useState(0);
  const atBottom = useRef(true);

  const filtered = applyFilters(entries, filters);

  const virtualizer = useVirtualizer({
    count:           filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize:    () => ROW_H,
    overscan:        10,
  });

  // Live tail: scroll to bottom when new entries arrive
  useEffect(() => {
    if (liveTail && atBottom.current && filtered.length > 0) {
      virtualizer.scrollToIndex(filtered.length - 1, { align: 'end' });
      setPendingCount(0);
    } else if (!liveTail && filtered.length > 0) {
      setPendingCount(c => c + 1);
    }
  }, [filtered.length, liveTail, virtualizer]);

  // Detect scroll position
  const onScroll = useCallback(() => {
    const el = parentRef.current;
    if (!el) return;
    const distFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    atBottom.current = distFromBottom < 10;

    // Pause live tail when user scrolls up
    if (distFromBottom > 200 && liveTail) onPause();

    // Load older entries when near top
    if (el.scrollTop < 150 && hasOlder && !loading) {
      actions.loadOlder();
    }

    // Load newer entries when near bottom (non-live-tail mode)
    if (distFromBottom < 150 && hasNewer && !loading && !liveTail) {
      actions.loadNewer();
    }
  }, [liveTail, hasOlder, hasNewer, loading, actions, onPause]);

  const items = virtualizer.getVirtualItems();

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {/* Column headers */}
      <div className="flex items-center bg-surface-2 border-b border-surface-3 text-[10px] text-slate-500 uppercase tracking-wider">
        <div className="w-20 px-3 py-1.5">Seq</div>
        <div className="w-36 px-3 py-1.5">Key</div>
        <div className="flex-1 px-3 py-1.5">Data</div>
        <div className="w-28 px-3 py-1.5">Time</div>
        <div className="w-32 px-3 py-1.5">Leaf Hash</div>
      </div>

      {/* Virtualised list */}
      <div ref={parentRef} className="flex-1 overflow-auto relative" onScroll={onScroll}>
        {loading && entries.length === 0 && (
          <div className="flex items-center justify-center h-32 text-slate-500 text-sm">Loading…</div>
        )}
        {error && (
          <div className="flex items-center justify-center h-32 text-accent-red text-sm">{error}</div>
        )}
        {!loading && !error && filtered.length === 0 && entries.length > 0 && (
          <div className="flex items-center justify-center h-32 text-slate-500 text-sm">No entries match the current filters.</div>
        )}

        <div style={{ height: `${virtualizer.getTotalSize()}px`, position: 'relative' }}>
          {items.map(item => {
            const entry = filtered[item.index];
            return (
              <EntryRow
                key={entry.seq}
                entry={entry}
                selected={selected?.seq === entry.seq}
                onClick={() => onSelect(entry)}
                style={{
                  position:  'absolute',
                  top:       0,
                  left:      0,
                  width:     '100%',
                  height:    `${item.size}px`,
                  transform: `translateY(${item.start}px)`,
                }}
              />
            );
          })}
        </div>
      </div>

      {/* Live tail banner */}
      {!liveTail && pendingCount > 0 && (
        <div className="bg-accent-blue/10 border-t border-accent-blue/20 px-4 py-2 flex items-center justify-between text-xs">
          <span className="text-accent-blue">{pendingCount} new {pendingCount === 1 ? 'entry' : 'entries'} since you scrolled up</span>
          <button
            onClick={() => {
              actions.jumpLatest();
              setPendingCount(0);
            }}
            className="text-accent-blue hover:text-white underline"
          >
            Resume live tail ↓
          </button>
        </div>
      )}

      {/* Status bar */}
      <div className="bg-surface-2 border-t border-surface-3 px-4 py-1 flex items-center gap-4 text-[10px] text-slate-500">
        <span>{filtered.length.toLocaleString()} entries shown</span>
        {filtered.length !== entries.length && (
          <span>({entries.length.toLocaleString()} loaded, filtered)</span>
        )}
        <span className="ml-auto flex items-center gap-1">
          <span className={clsx('w-1.5 h-1.5 rounded-full', connected ? 'bg-accent-green' : 'bg-accent-red')} />
          {connected ? 'Live' : 'Disconnected'}
        </span>
      </div>
    </div>
  );
}
