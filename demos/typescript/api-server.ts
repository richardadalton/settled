import * as http from 'node:http';
import { SettledClient } from '@daltonr/settled-sdk';

const GRPC_ADDR = process.env['SETTLED_ADDR'] ?? 'localhost:50051';
const PORT = Number(process.env['PORT'] ?? 3001);

const client = new SettledClient(GRPC_ADDR);

const enc = new TextEncoder();
const dec = new TextDecoder();

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

function cors(res: http.ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function json(res: http.ServerResponse, data: unknown, status = 200): void {
  cors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

async function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);

  if (req.method === 'OPTIONS') {
    cors(res);
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    if (url.pathname === '/api/entries' && req.method === 'GET') {
      const entries: unknown[] = [];
      let cursor = 0n;
      do {
        const page = await client.listEntries(0n, 0n, cursor);
        for (const e of page.entries) {
          entries.push({
            seq: String(e.seq),
            key: dec.decode(e.key),
            data: dec.decode(e.data),
            timestampNs: String(e.timestampNs),
            leafHash: hex(e.leafHash),
          });
        }
        cursor = page.nextCursor;
      } while (cursor !== 0n);
      return json(res, entries);
    }

    if (url.pathname === '/api/entries' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req)) as { key: string; data: string };
      const result = await client.append(enc.encode(body.key), enc.encode(body.data));
      return json(res, {
        seq: String(result.seq),
        timestampNs: String(result.timestampNs),
        leafHash: hex(result.leafHash),
      });
    }

    if (url.pathname === '/api/entries/by-key' && req.method === 'GET') {
      const key = url.searchParams.get('key');
      if (!key) return json(res, { error: 'key is required' }, 400);
      const cursor = BigInt(url.searchParams.get('cursor') ?? '0');
      const limit  = Number(url.searchParams.get('limit') ?? 0);

      const entries: unknown[] = [];
      let nextCursor = cursor;
      do {
        const page = await client.getByKey(enc.encode(key), nextCursor, limit);
        for (const e of page.entries) {
          entries.push({
            seq: String(e.seq),
            key: dec.decode(e.key),
            data: dec.decode(e.data),
            timestampNs: String(e.timestampNs),
            leafHash: hex(e.leafHash),
          });
        }
        nextCursor = page.nextCursor;
      } while (nextCursor !== 0n && limit === 0);

      return json(res, { entries, next_cursor: String(nextCursor) });
    }

    json(res, { error: 'not found' }, 404);
  } catch (e) {
    json(res, { error: String(e) }, 500);
  }
});

server.listen(PORT, () => {
  console.log(`API server → http://localhost:${PORT}  (gRPC: ${GRPC_ADDR})`);
});
