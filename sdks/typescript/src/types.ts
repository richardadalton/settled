export interface SignedTreeHead {
  treeSize: bigint;
  rootHash: Uint8Array;
  timestampNs: bigint;
  signature: Uint8Array;
  publicKey: Uint8Array;
  keyVersion: number;
}

export interface Entry {
  seq: bigint;
  timestampNs: bigint;
  key: Uint8Array;
  data: Uint8Array;
  leafHash: Uint8Array;
}

export interface AppendResult {
  seq: bigint;
  timestampNs: bigint;
  leafHash: Uint8Array;
}

export interface InclusionProofResult {
  leafIndex: bigint;
  treeSize: bigint;
  proof: Uint8Array[];
  sth: SignedTreeHead;
}

export interface ConsistencyProofResult {
  oldSize: bigint;
  newSize: bigint;
  proof: Uint8Array[];
  oldSth: SignedTreeHead;
  newSth: SignedTreeHead;
}

export interface GetLatestResult {
  entries: Entry[];
  /** Total entries in the log. Greater than entries.length means the result
   *  was capped; use listEntries to page through older entries. */
  totalAvailable: bigint;
}

export interface ListEntriesResult {
  entries: Entry[];
  /** Pass as `cursor` in the next call. `0n` means no more pages. */
  nextCursor: bigint;
}

export interface GetByKeyResult {
  entries: Entry[];
  /** Pass as `cursor` in the next call. `0n` means no more pages. */
  nextCursor: bigint;
}
