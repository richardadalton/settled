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
