import { useEffect, useRef, useCallback, useState } from 'react';
import type { Entry, Sth, SseEvent } from '../types.js';

type Handlers = {
  onEntry: (e: Entry) => void;
  onSth:   (s: Sth)   => void;
};

export function useLiveTail({ onEntry, onSth }: Handlers) {
  const [connected, setConnected]     = useState(false);
  const [liveTail,  setLiveTail]      = useState(true);
  const esRef = useRef<EventSource | null>(null);

  const connect = useCallback(() => {
    if (esRef.current) esRef.current.close();
    const es = new EventSource('/api/events');
    esRef.current = es;

    es.addEventListener('entry', (e: MessageEvent) => {
      onEntry(JSON.parse(e.data) as Entry);
    });
    es.addEventListener('sth', (e: MessageEvent) => {
      onSth(JSON.parse(e.data) as Sth);
    });
    es.addEventListener('open', () => setConnected(true));
    es.addEventListener('error', () => setConnected(false));
  }, [onEntry, onSth]);

  useEffect(() => {
    connect();
    return () => { esRef.current?.close(); esRef.current = null; };
  }, [connect]);

  return {
    connected,
    liveTail,
    pauseLiveTail:  () => setLiveTail(false),
    resumeLiveTail: () => setLiveTail(true),
  };
}
