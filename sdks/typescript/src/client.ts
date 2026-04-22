import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type {
  AppendResult,
  ConsistencyProofResult,
  Entry,
  InclusionProofResult,
  SignedTreeHead,
} from './types.js';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.resolve(__dirname, '../proto/settled.v1.proto');

function loadServiceStub(): grpc.ServiceClientConstructor {
  const packageDef = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const pkg = grpc.loadPackageDefinition(packageDef) as Record<string, unknown>;
  const settled = pkg['settled'] as Record<string, unknown>;
  const v1 = settled['v1'] as Record<string, unknown>;
  return v1['SettledLog'] as grpc.ServiceClientConstructor;
}

// ── Wire type helpers ─────────────────────────────────────────────────────────

// proto-loader with longs:String gives string for uint64/int64
// and Buffer for bytes fields.

function toBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  return new Uint8Array(0);
}

function toBigInt(v: unknown): bigint {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'string') return BigInt(v);
  if (typeof v === 'number') return BigInt(v);
  return 0n;
}

function toNum(v: unknown): number {
  return Number(v ?? 0);
}

function fromSth(raw: Record<string, unknown>): SignedTreeHead {
  return {
    treeSize: toBigInt(raw['tree_size']),
    rootHash: toBytes(raw['root_hash']),
    timestampNs: toBigInt(raw['timestamp_ns']),
    signature: toBytes(raw['signature']),
    publicKey: toBytes(raw['public_key']),
    keyVersion: toNum(raw['key_version']),
  };
}

// ── SettledClient ─────────────────────────────────────────────────────────────

export interface ClientOptions {
  /** Reconnect on transient failures. Default: true. */
  reconnect?: boolean;
}

export class SettledClient {
  private readonly stub: grpc.Client;

  constructor(address: string, options: ClientOptions = {}) {
    const SettledLog = loadServiceStub();
    const channelOptions: grpc.ChannelOptions = {};
    if (options.reconnect !== false) {
      channelOptions['grpc.enable_retries'] = 1;
    }
    this.stub = new SettledLog(address, grpc.credentials.createInsecure(), channelOptions);
  }

  close(): void {
    this.stub.close();
  }

  /** Wait until the channel is ready or the deadline is reached. */
  waitForReady(deadlineMs = 5000): Promise<void> {
    return new Promise((resolve, reject) => {
      this.stub.waitForReady(Date.now() + deadlineMs, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  append(key: Uint8Array, data: Uint8Array): Promise<AppendResult> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['append'](
        { key, data },
        (err: grpc.ServiceError | null, res: Record<string, unknown>) => {
          if (err) return reject(err);
          resolve({
            seq: toBigInt(res['seq']),
            timestampNs: toBigInt(res['timestamp_ns']),
            leafHash: toBytes(res['leaf_hash']),
          });
        },
      );
    });
  }

  get(seq: bigint): Promise<Entry> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['get'](
        { seq: seq.toString() },
        (err: grpc.ServiceError | null, res: Record<string, unknown>) => {
          if (err) return reject(err);
          const e = res['entry'] as Record<string, unknown>;
          resolve({
            seq: toBigInt(e['seq']),
            timestampNs: toBigInt(e['timestamp_ns']),
            key: toBytes(e['key']),
            data: toBytes(e['data']),
            leafHash: toBytes(e['leaf_hash']),
          });
        },
      );
    });
  }

  getSth(treeSize: bigint = 0n): Promise<SignedTreeHead> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['getSth'](
        { tree_size: treeSize.toString() },
        (err: grpc.ServiceError | null, res: Record<string, unknown>) => {
          if (err) return reject(err);
          resolve(fromSth(res['sth'] as Record<string, unknown>));
        },
      );
    });
  }

  inclusionProof(seq: bigint, treeSize: bigint = 0n): Promise<InclusionProofResult> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['inclusionProof'](
        { seq: seq.toString(), tree_size: treeSize.toString() },
        (err: grpc.ServiceError | null, res: Record<string, unknown>) => {
          if (err) return reject(err);
          resolve({
            leafIndex: toBigInt(res['leaf_index']),
            treeSize: toBigInt(res['tree_size']),
            proof: (res['proof'] as unknown[]).map(toBytes),
            sth: fromSth(res['sth'] as Record<string, unknown>),
          });
        },
      );
    });
  }

  consistencyProof(oldSize: bigint, newSize: bigint = 0n): Promise<ConsistencyProofResult> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['consistencyProof'](
        { old_size: oldSize.toString(), new_size: newSize.toString() },
        (err: grpc.ServiceError | null, res: Record<string, unknown>) => {
          if (err) return reject(err);
          resolve({
            oldSize: toBigInt(res['old_size']),
            newSize: toBigInt(res['new_size']),
            proof: (res['proof'] as unknown[]).map(toBytes),
            oldSth: fromSth(res['old_sth'] as Record<string, unknown>),
            newSth: fromSth(res['new_sth'] as Record<string, unknown>),
          });
        },
      );
    });
  }

  /**
   * Stream entries to the server in batches.
   * Yields an AppendResult for each entry in input order.
   * Applies back-pressure when the in-flight batch count reaches batchSize.
   */
  async *appendStream(
    entries: AsyncIterable<{ key: Uint8Array; data: Uint8Array }>,
    options: { batchSize?: number; flushIntervalMs?: number } = {},
  ): AsyncIterable<AppendResult> {
    const batchSize = options.batchSize ?? 100;
    const flushIntervalMs = options.flushIntervalMs ?? 50;

    let batch: Array<{ key: Uint8Array; data: Uint8Array }> = [];
    let flushTimer: ReturnType<typeof setTimeout> | null = null;
    const pending: Array<Promise<AppendResult[]>> = [];

    const flush = (): void => {
      if (batch.length === 0) return;
      const toSend = batch;
      batch = [];
      const batchPromise = Promise.all(toSend.map((e) => this.append(e.key, e.data)));
      pending.push(batchPromise);
    };

    const resetTimer = (): void => {
      if (flushTimer) clearTimeout(flushTimer);
      flushTimer = setTimeout(flush, flushIntervalMs);
    };

    for await (const entry of entries) {
      batch.push(entry);
      resetTimer();
      if (batch.length >= batchSize) {
        if (flushTimer) clearTimeout(flushTimer);
        flushTimer = null;
        flush();
      }
      // Drain completed batches to yield results and bound memory.
      while (pending.length > 0 && pending[0] !== undefined) {
        const results = await pending.shift()!;
        for (const r of results) yield r;
      }
    }

    if (flushTimer) clearTimeout(flushTimer);
    flush();
    for (const p of pending) {
      const results = await p;
      for (const r of results) yield r;
    }
  }
}
