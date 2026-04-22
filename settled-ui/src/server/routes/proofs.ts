import { Router } from 'express';
import { rpc, GrpcInclusionResponse, GrpcConsistencyResponse } from '../grpc.js';
import { proofCache } from '../cache.js';
import { serializeSth } from './sth.js';

export const proofsRouter = Router();

// GET /api/entries/:seq/proof
proofsRouter.get('/:seq/proof', async (req, res) => {
  const seq = Number(req.params['seq']);
  if (!Number.isInteger(seq) || seq < 0) {
    res.status(400).json({ error: 'invalid seq' });
    return;
  }

  // Fetch proof at latest tree size; the cache key includes tree_size so stale
  // proofs are never returned for a newer tree.
  const result = await rpc<GrpcInclusionResponse>('inclusionProof', {
    seq: String(seq),
    tree_size: '0',
  });

  const cacheKey = `${seq}:${result.tree_size}`;
  const cached = proofCache.get(cacheKey);
  if (cached) {
    res.json(cached);
    return;
  }

  const serialized = {
    leaf_index: Number(result.leaf_index),
    tree_size:  Number(result.tree_size),
    proof:      result.proof.map((h: Buffer) => Buffer.from(h).toString('hex')),
    sth:        serializeSth(result.sth),
  };

  proofCache.set(cacheKey, serialized);
  res.json(serialized);
});

// GET /api/consistency?old=M&new=N
proofsRouter.get('/consistency', async (req, res) => {
  const oldSize = Number(req.query['old'] ?? 0);
  const newSize = Number(req.query['new'] ?? 0);

  if (!Number.isInteger(oldSize) || !Number.isInteger(newSize) || oldSize < 0 || newSize < 0) {
    res.status(400).json({ error: 'invalid tree sizes' });
    return;
  }

  const result = await rpc<GrpcConsistencyResponse>('consistencyProof', {
    old_size: String(oldSize),
    new_size: String(newSize),
  });

  res.json({
    old_size: Number(result.old_size),
    new_size: Number(result.new_size),
    proof:    result.proof.map((h: Buffer) => Buffer.from(h).toString('hex')),
    old_sth:  serializeSth(result.old_sth),
    new_sth:  serializeSth(result.new_sth),
  });
});
