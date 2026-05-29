import { Router, Request, Response } from 'express';
import { stub } from '../grpc.js';
import type { GrpcEntry } from '../grpc.js';

export const eventsRouter = Router();

const PING_INTERVAL_MS = 15_000;
const RECONNECT_DELAY_MS = 5_000;

// ── SSE helpers ───────────────────────────────────────────────────────────────

function send(res: Response, event: string, data: unknown): void {
  try {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  } catch {
    // ignore write errors on closed connections
  }
}

function serializeEntry(raw: Record<string, unknown>) {
  return {
    seq:          Number(raw['seq']),
    key:          Buffer.from(raw['key'] as Buffer).toString(),
    data:         Buffer.from(raw['data'] as Buffer).toString(),
    timestamp_ns: String(raw['timestamp_ns']),
    leaf_hash:    Buffer.from(raw['leaf_hash'] as Buffer).toString('hex'),
  };
}

// ── Shared Watch subscription ────────────────────────────────────────────────
// One gRPC Watch stream feeds all active SSE connections.

const sseClients = new Set<Response>();

function broadcast(event: string, data: unknown): void {
  for (const res of sseClients) send(res, event, data);
}

let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

function startWatch(): void {
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }

  const call = (stub as unknown as Record<string, Function>)['watch'](
    { from_seq: '0' },
  ) as import('events').EventEmitter & { cancel(): void };

  call.on('data', (raw: Record<string, unknown>) => {
    broadcast('entry', serializeEntry(raw));
  });

  const scheduleReconnect = () => {
    reconnectTimer = setTimeout(startWatch, RECONNECT_DELAY_MS);
  };
  call.on('error', scheduleReconnect);
  call.on('end',   scheduleReconnect);
}

startWatch();

// ── SSE endpoint ─────────────────────────────────────────────────────────────

eventsRouter.get('/', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch { /* ignore */ } }, PING_INTERVAL_MS);
  sseClients.add(res);

  req.on('close', () => {
    sseClients.delete(res);
    clearInterval(ping);
  });
});
