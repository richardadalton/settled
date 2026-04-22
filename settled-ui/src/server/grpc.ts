import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// In production the Dockerfile copies proto/ to /proto.
// In development it sits three levels up from src/server/.
const PROTO_PATH = process.env['NODE_ENV'] === 'production'
  ? '/proto/settled.v1.proto'
  : path.resolve(__dirname, '../../../proto/settled.v1.proto');

const GRPC_ADDR = process.env['SETTLED_ADDR'] ?? 'localhost:50051';

const packageDef = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  defaults: true,
  includeDirs: [path.resolve(__dirname, '../../../proto')],
});

const pkg = grpc.loadPackageDefinition(packageDef) as Record<string, unknown>;
const svc = (pkg['settled'] as Record<string, unknown>)['v1'] as Record<string, grpc.ServiceClientConstructor>;
export const stub = new svc['SettledLog'](GRPC_ADDR, grpc.credentials.createInsecure());

export function rpc<T>(method: string, req: Record<string, unknown>): Promise<T> {
  return new Promise((resolve, reject) => {
    (stub as unknown as Record<string, Function>)[method](
      req,
      (err: grpc.ServiceError | null, res: T) => {
        if (err) reject(err); else resolve(res);
      },
    );
  });
}

export type GrpcEntry = {
  seq: string;
  timestamp_ns: string;
  key: Buffer;
  data: Buffer;
  leaf_hash: Buffer;
};

export type GrpcSth = {
  tree_size: string;
  root_hash: Buffer;
  timestamp_ns: string;
  signature: Buffer;
  public_key: Buffer;
  key_version: number;
};

export type GrpcGetResponse      = { entry: GrpcEntry };
export type GrpcGetSthResponse   = { sth: GrpcSth };
export type GrpcInclusionResponse = {
  leaf_index: string;
  tree_size: string;
  proof: Buffer[];
  sth: GrpcSth;
};
export type GrpcConsistencyResponse = {
  old_size: string;
  new_size: string;
  proof: Buffer[];
  old_sth: GrpcSth;
  new_sth: GrpcSth;
};
