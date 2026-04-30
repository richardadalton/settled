import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api.js';
import { verifySth } from '../lib/verify.js';
import type { Sth, VerifyStatus } from '../types.js';

export type SthState = {
  sth:    Sth | null;
  status: VerifyStatus;
  error:  string | null;
};

const POLL_MS = 62_000; // slightly longer than server signing interval

export function useSth(): SthState {
  const [state, setState] = useState<SthState>({ sth: null, status: 'idle', error: null });

  const load = useCallback(async () => {
    try {
      const sth = await api.sth();
      setState({ sth, status: 'verifying', error: null });
      const result = await verifySth(sth);
      setState({ sth, status: result.ok ? 'verified' : 'failed', error: result.ok ? null : result.reason });
    } catch (e) {
      setState(prev => ({ ...prev, status: 'failed', error: String(e) }));
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  return state;
}
