import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type {
  AppendResult,
  ConsistencyProofResult,
  Entry,
  GetByKeyResult,
  GetLatestResult,
  InclusionProofResult,
  ListEntriesResult,
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
  /** API key sent as `authorization: Bearer <key>` on every request. */
  apiKey?: string;
}

export class SettledClient {
  private readonly stub: grpc.Client;
  private readonly metadata: grpc.Metadata;

  constructor(address: string, options: ClientOptions = {}) {
    const SettledLog = loadServiceStub();
    const channelOptions: grpc.ChannelOptions = {};
    if (options.reconnect !== false) {
      channelOptions['grpc.enable_retries'] = 1;
    }
    this.stub = new SettledLog(address, grpc.credentials.createInsecure(), channelOptions);
    this.metadata = new grpc.Metadata();
    if (options.apiKey) {
      this.metadata.set('authorization', `Bearer ${options.apiKey}`);
    }
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
        this.metadata,
        (err: grpc.ServiceError | null, res: Record<string, unknown>) => {
          if (err) return reject(err);
          resolve({
            seq: toBigInt(res['seq']),
            timestampNs: toBigInt(res['timestamp_ns']),
            leafHash: toBytes(res['leaf_hash']),
            key: toBytes(res['key']),
          });
        },
      );
    });
  }

  get(seq: bigint): Promise<Entry> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['get'](
        { seq: seq.toString() },
        this.metadata,
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

  /**
   * Fetch the most-recent ``n`` entries (newest first).
   *
   * ``n = 0`` is treated as 1 by the server. Values above the server cap
   * (currently 1000) are silently clamped. Check ``totalAvailable`` to
   * detect truncation; use ``listEntries`` to page through older entries.
   */
  getLatest(n = 1): Promise<GetLatestResult> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['getLatest'](
        { n },
        this.metadata,
        (err: grpc.ServiceError | null, res: Record<string, unknown>) => {
          if (err) return reject(err);
          const entries = ((res['entries'] as unknown[]) ?? []).map((raw) => {
            const e = raw as Record<string, unknown>;
            return {
              seq: toBigInt(e['seq']),
              timestampNs: toBigInt(e['timestamp_ns']),
              key: toBytes(e['key']),
              data: toBytes(e['data']),
              leafHash: toBytes(e['leaf_hash']),
            } satisfies Entry;
          });
          resolve({ entries, totalAvailable: toBigInt(res['total_available']) });
        },
      );
    });
  }

  getSth(treeSize: bigint = 0n): Promise<SignedTreeHead> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['getSth'](
        { tree_size: treeSize.toString() },
        this.metadata,
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
        this.metadata,
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

  /**
   * Open a server-streaming Watch RPC.
   *
   * `fromSeq > 0n`: replays entries from that seq, then continues live.
   * `fromSeq == 0n` (default): streams only entries appended after the call.
   *
   * Returns an `AsyncIterable<Entry>` — use `for await...of` to consume it.
   * Call `.return()` on the iterator (or break from the loop) to cancel.
   */
  watchEntries(fromSeq: bigint = 0n): AsyncIterable<Entry> {
    const call = (this.stub as unknown as Record<string, Function>)['watch'](
      { from_seq: fromSeq.toString() },
      this.metadata,
    ) as import('events').EventEmitter & { cancel(): void };

    return {
      [Symbol.asyncIterator](): AsyncIterator<Entry> {
        type Waiter = (v: IteratorResult<Entry>) => void;
        const queue: Array<Entry | Error | null> = [];
        let waiter: Waiter | null = null;

        const push = (item: Entry | Error | null) => {
          if (waiter) {
            const w = waiter;
            waiter = null;
            if (item === null) w({ done: true, value: undefined as unknown as Entry });
            else if (item instanceof Error) w(Promise.reject(item) as unknown as IteratorResult<Entry>);
            else w({ done: false, value: item });
          } else {
            queue.push(item);
          }
        };

        call.on('data', (raw: Record<string, unknown>) => {
          push({
            seq: toBigInt(raw['seq']),
            timestampNs: toBigInt(raw['timestamp_ns']),
            key: toBytes(raw['key']),
            data: toBytes(raw['data']),
            leafHash: toBytes(raw['leaf_hash']),
          });
        });
        call.on('end', () => push(null));
        call.on('error', (err: Error) => push(err));

        return {
          next(): Promise<IteratorResult<Entry>> {
            if (queue.length > 0) {
              const item = queue.shift()!;
              if (item === null) return Promise.resolve({ done: true, value: undefined as unknown as Entry });
              if (item instanceof Error) return Promise.reject(item);
              return Promise.resolve({ done: false, value: item });
            }
            return new Promise<IteratorResult<Entry>>((resolve, reject) => {
              waiter = (v) => {
                if (v instanceof Promise) v.then(resolve, reject);
                else resolve(v);
              };
            });
          },
          return(): Promise<IteratorResult<Entry>> {
            call.cancel();
            return Promise.resolve({ done: true, value: undefined as unknown as Entry });
          },
        };
      },
    };
  }

  /**
   * Retrieve a page of entries in seq order within `[fromSeq, toSeq)`.
   * `toSeq = 0n` scans to the end of the log. Pass `cursor = 0n` to start
   * from `fromSeq`; pass `nextCursor` from the previous response to page.
   * `limit = 0` uses the server default (50).
   */
  listEntries(
    fromSeq: bigint = 0n,
    toSeq: bigint = 0n,
    cursor: bigint = 0n,
    limit = 0,
  ): Promise<ListEntriesResult> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['listEntries'](
        {
          from_seq: fromSeq.toString(),
          to_seq: toSeq.toString(),
          cursor: cursor.toString(),
          limit,
        },
        this.metadata,
        (err: grpc.ServiceError | null, res: Record<string, unknown>) => {
          if (err) return reject(err);
          const entries = ((res['entries'] as unknown[]) ?? []).map((raw) => {
            const e = raw as Record<string, unknown>;
            return {
              seq: toBigInt(e['seq']),
              timestampNs: toBigInt(e['timestamp_ns']),
              key: toBytes(e['key']),
              data: toBytes(e['data']),
              leafHash: toBytes(e['leaf_hash']),
            } satisfies Entry;
          });
          resolve({ entries, nextCursor: toBigInt(res['next_cursor']) });
        },
      );
    });
  }

  /**
   * Retrieve all entries for a given key with cursor-based pagination.
   * Pass `cursor = 0n` to start from the beginning. `limit = 0` uses the
   * server default (50). `nextCursor === 0n` in the result means no more pages.
   */
  getByKey(key: Uint8Array, cursor: bigint = 0n, limit = 0): Promise<GetByKeyResult> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['getByKey'](
        { key, cursor: cursor.toString(), limit },
        this.metadata,
        (err: grpc.ServiceError | null, res: Record<string, unknown>) => {
          if (err) return reject(err);
          const entries = ((res['entries'] as unknown[]) ?? []).map((raw) => {
            const e = raw as Record<string, unknown>;
            return {
              seq: toBigInt(e['seq']),
              timestampNs: toBigInt(e['timestamp_ns']),
              key: toBytes(e['key']),
              data: toBytes(e['data']),
              leafHash: toBytes(e['leaf_hash']),
            } satisfies Entry;
          });
          resolve({
            entries,
            nextCursor: toBigInt(res['next_cursor']),
          });
        },
      );
    });
  }

  consistencyProof(oldSize: bigint, newSize: bigint = 0n): Promise<ConsistencyProofResult> {
    return new Promise((resolve, reject) => {
      (this.stub as unknown as Record<string, Function>)['consistencyProof'](
        { old_size: oldSize.toString(), new_size: newSize.toString() },
        this.metadata,
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
