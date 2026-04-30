import { Router } from 'express';
import { rpc, GrpcGetResponse, GrpcGetSthResponse } from '../grpc.js';
import { entryCache } from '../cache.js';

export const entriesRouter = Router();

const MAX_LIMIT = 100;

function serializeEntry(e: GrpcGetResponse['entry']) {
  return {
    seq:          Number(e.seq),
    key:          Buffer.from(e.key).toString(),
    data:         Buffer.from(e.data).toString(),
    timestamp_ns: String(e.timestamp_ns),
    leaf_hash:    Buffer.from(e.leaf_hash).toString('hex'),
  };
}

async function fetchEntry(seq: number): Promise<unknown> {
  const key = String(seq);
  const cached = entryCache.get(key);
  if (cached) return cached;

  const result = await rpc<GrpcGetResponse>('get', { seq: key });
  const serialized = serializeEntry(result.entry);
  entryCache.set(key, serialized);
  return serialized;
}

// GET /api/entries?from=N&limit=M&dir=asc|desc
entriesRouter.get('/', async (req, res) => {
  const sthResult = await rpc<GrpcGetSthResponse>('getSth', { tree_size: '0' });
  const treeSize = Number(sthResult.sth.tree_size);

  if (treeSize === 0) {
    res.json({ entries: [], tree_size: 0 });
    return;
  }

  const dir   = req.query['dir'] === 'desc' ? 'desc' : 'asc';
  const limit = Math.min(Number(req.query['limit'] ?? 50), MAX_LIMIT);
  const from  = req.query['from'] !== undefined
    ? Math.max(0, Math.min(Number(req.query['from']), treeSize - 1))
    : (dir === 'asc' ? 0 : treeSize - 1);

  const seqs: number[] = [];
  if (dir === 'asc') {
    for (let i = from; i < treeSize && seqs.length < limit; i++) seqs.push(i);
  } else {
    for (let i = from; i >= 0 && seqs.length < limit; i--) seqs.push(i);
  }

  const entries = await Promise.all(seqs.map(fetchEntry));
  res.json({ entries, tree_size: treeSize });
});

// GET /api/entries/:seq
entriesRouter.get('/:seq', async (req, res) => {
  const seq = Number(req.params['seq']);
  if (!Number.isInteger(seq) || seq < 0) {
    res.status(400).json({ error: 'invalid seq' });
    return;
  }
  const entry = await fetchEntry(seq);
  res.json(entry);
});
