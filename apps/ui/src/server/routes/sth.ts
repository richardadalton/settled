import { Router } from 'express';
import { rpc, GrpcGetSthResponse } from '../grpc.js';
import { getCachedSth, setCachedSth } from '../cache.js';

export const sthRouter = Router();

function serializeSth(sth: GrpcGetSthResponse['sth']) {
  return {
    tree_size:   Number(sth.tree_size),
    root_hash:   Buffer.from(sth.root_hash).toString('hex'),
    timestamp_ns: String(sth.timestamp_ns),
    signature:   Buffer.from(sth.signature).toString('hex'),
    public_key:  Buffer.from(sth.public_key).toString('hex'),
    key_version: sth.key_version,
  };
}

sthRouter.get('/', async (_req, res) => {
  const cached = getCachedSth();
  if (cached) {
    res.json(cached);
    return;
  }

  const result = await rpc<GrpcGetSthResponse>('getSth', { tree_size: '0' });
  const serialized = serializeSth(result.sth);
  setCachedSth(serialized);
  res.json(serialized);
});

export { serializeSth };
