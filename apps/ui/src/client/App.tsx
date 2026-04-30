import { useState, useCallback } from 'react';
import { SthHeader } from './components/SthHeader.js';
import { FilterBar } from './components/FilterBar.js';
import { EntryList } from './components/EntryList.js';
import { EntryDetail } from './components/EntryDetail.js';
import { useSth } from './hooks/useSth.js';
import { useEntries } from './hooks/useEntries.js';
import { useLiveTail } from './hooks/useLiveTail.js';
import type { Entry, Sth } from './types.js';
import type { Filters } from './components/FilterBar.js';

const EMPTY_FILTERS: Filters = { key: '', data: '', fromSeq: '', toSeq: '' };

export function App() {
  const sthState = useSth();
  const [entriesState, actions] = useEntries();
  const [filters,  setFilters]  = useState<Filters>(EMPTY_FILTERS);
  const [selected, setSelected] = useState<Entry | null>(null);

  const handleEntry = useCallback((entry: Entry) => {
    actions.appendLive(entry);
  }, [actions]);

  const handleSth = useCallback((sth: Sth) => {
    actions.setTreeSize(sth.tree_size);
  }, [actions]);

  const { connected, liveTail, pauseLiveTail, resumeLiveTail } = useLiveTail({
    onEntry: handleEntry,
    onSth:   handleSth,
  });

  return (
    <div className="flex flex-col h-screen overflow-hidden">
      <SthHeader state={sthState} />

      <FilterBar
        filters={filters}
        onChange={setFilters}
        treeSize={entriesState.treeSize}
        onSeek={seq => { pauseLiveTail(); actions.seekTo(seq); }}
        onJumpFirst={() => { pauseLiveTail(); actions.jumpFirst(); }}
        onJumpLatest={() => { resumeLiveTail(); actions.jumpLatest(); }}
      />

      <EntryList
        state={entriesState}
        actions={actions}
        filters={filters}
        liveTail={liveTail}
        onPause={pauseLiveTail}
        onSelect={setSelected}
        selected={selected}
        connected={connected}
      />

      <EntryDetail entry={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
