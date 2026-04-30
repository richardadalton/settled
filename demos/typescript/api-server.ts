import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.resolve(__dirname, '../../proto/settled.v1.proto');

const GRPC_ADDR = process.env['SETTLED_ADDR'] ?? 'localhost:50051';
const PORT = Number(process.env['PORT'] ?? 3001);

const packageDef = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  defaults: true,
});
const pkg = grpc.loadPackageDefinition(packageDef) as Record<string, unknown>;
const SettledLog = (pkg['settled'] as Record<string, unknown>)['v1'] as Record<string, grpc.ServiceClientConstructor>;
const stub = new SettledLog['SettledLog'](GRPC_ADDR, grpc.credentials.createInsecure());

function call<T>(method: string, req: Record<string, unknown>): Promise<T> {
  return new Promise((resolve, reject) => {
    (stub as unknown as Record<string, Function>)[method](
      req,
      (err: grpc.ServiceError | null, res: T) => {
        if (err) reject(err); else resolve(res);
      },
    );
  });
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
      const sthRes = await call<Record<string, Record<string, string>>>('getSth', { tree_size: '0' });
      const treeSize = Number(sthRes['sth']['tree_size']);

      const entries = await Promise.all(
        Array.from({ length: treeSize }, (_, i) =>
          call<Record<string, Record<string, Buffer | string>>>('get', { seq: String(i) }).then((r) => {
            const e = r['entry'];
            return {
              seq: String(e['seq']),
              key: Buffer.from(e['key'] as Buffer).toString(),
              data: Buffer.from(e['data'] as Buffer).toString(),
              timestampNs: String(e['timestamp_ns']),
              leafHash: Buffer.from(e['leaf_hash'] as Buffer).toString('hex'),
            };
          }),
        ),
      );

      return json(res, entries);
    }

    if (url.pathname === '/api/entries' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req)) as { key: string; data: string };
      const enc = new TextEncoder();
      const result = await call<Record<string, Buffer | string>>('append', {
        key: enc.encode(body.key),
        data: enc.encode(body.data),
      });
      return json(res, {
        seq: String(result['seq']),
        timestampNs: String(result['timestamp_ns']),
        leafHash: Buffer.from(result['leaf_hash'] as Buffer).toString('hex'),
      });
    }

    json(res, { error: 'not found' }, 404);
  } catch (e) {
    json(res, { error: String(e) }, 500);
  }
});

server.listen(PORT, () => {
  console.log(`API server → http://localhost:${PORT}  (gRPC: ${GRPC_ADDR})`);
});
