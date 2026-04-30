import { Router, Request, Response } from 'express';
import { rpc, GrpcGetSthResponse, GrpcGetResponse } from '../grpc.js';
import { entryCache } from '../cache.js';

export const eventsRouter = Router();

const POLL_INTERVAL_MS = 10_000;
const PING_INTERVAL_MS = 15_000;

function serializeSth(sth: GrpcGetSthResponse['sth']) {
  return {
    tree_size:    Number(sth.tree_size),
    root_hash:    Buffer.from(sth.root_hash).toString('hex'),
    timestamp_ns: String(sth.timestamp_ns),
    signature:    Buffer.from(sth.signature).toString('hex'),
    public_key:   Buffer.from(sth.public_key).toString('hex'),
    key_version:  sth.key_version,
  };
}

function send(res: Response, event: string, data: unknown) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

eventsRouter.get('/', async (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  let knownSize = 0;
  let alive = true;

  const ping = setInterval(() => {
    if (alive) send(res, 'ping', {});
  }, PING_INTERVAL_MS);

  async function poll() {
    if (!alive) return;
    try {
      const sthResult = await rpc<GrpcGetSthResponse>('getSth', { tree_size: '0' });
      const sth = sthResult.sth;
      const newSize = Number(sth.tree_size);

      if (newSize !== knownSize) {
        send(res, 'sth', serializeSth(sth));

        // Fetch and emit each new entry, capped at 200 per poll to avoid flooding
        const fetchFrom = knownSize;
        const fetchTo   = Math.min(newSize, fetchFrom + 200);
        for (let seq = fetchFrom; seq < fetchTo; seq++) {
          if (!alive) break;
          try {
            const cacheKey = String(seq);
            let entry = entryCache.get(cacheKey);
            if (!entry) {
              const r = await rpc<GrpcGetResponse>('get', { seq: cacheKey });
              entry = {
                seq:          Number(r.entry.seq),
                key:          Buffer.from(r.entry.key).toString(),
                data:         Buffer.from(r.entry.data).toString(),
                timestamp_ns: String(r.entry.timestamp_ns),
                leaf_hash:    Buffer.from(r.entry.leaf_hash).toString('hex'),
              };
              entryCache.set(cacheKey, entry);
            }
            send(res, 'entry', entry);
          } catch {
            // individual entry fetch failure is non-fatal
          }
        }
        knownSize = newSize;
      }
    } catch {
      // gRPC unavailable — will retry next poll
    }

    if (alive) setTimeout(poll, POLL_INTERVAL_MS);
  }

  req.on('close', () => {
    alive = false;
    clearInterval(ping);
  });

  // Initial poll immediately
  poll();
});
