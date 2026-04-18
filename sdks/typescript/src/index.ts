export type {
  AppendResult,
  ConsistencyProofResult,
  Entry,
  InclusionProofResult,
  SignedTreeHead,
} from './types.js';

export { SettledClient } from './client.js';
export type { ClientOptions } from './client.js';

export {
  leafHash,
  nodeHash,
  verifyInclusion,
  verifyConsistency,
  verifyTreeHead,
  signingPayload,
} from './verifier.js';
