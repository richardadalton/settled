export type Sth = {
  tree_size:    number;
  root_hash:    string;  // hex
  timestamp_ns: string;
  signature:    string;  // hex
  public_key:   string;  // hex
  key_version:  number;
};

export type Entry = {
  seq:          number;
  key:          string;
  data:         string;
  timestamp_ns: string;
  leaf_hash:    string;  // hex
};

export type EntriesResponse = {
  entries:   Entry[];
  tree_size: number;
};

export type InclusionProof = {
  leaf_index: number;
  tree_size:  number;
  proof:      string[];  // hex array, RFC 6962 PATH
  sth:        Sth;
};

export type ConsistencyProof = {
  old_size: number;
  new_size: number;
  proof:    string[];
  old_sth:  Sth;
  new_sth:  Sth;
};

export type VerifyStatus = 'idle' | 'verifying' | 'verified' | 'failed';

export type SseEvent =
  | { type: 'sth';   data: Sth }
  | { type: 'entry'; data: Entry }
  | { type: 'ping';  data: Record<string, never> };
