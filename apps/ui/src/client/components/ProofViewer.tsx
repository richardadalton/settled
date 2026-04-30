import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import { Badge } from './Badge.js';
import { api } from '../lib/api.js';
import { verifyInclusion } from '../lib/verify.js';
import type { Entry, InclusionProof, VerifyStatus } from '../types.js';
import type { InclusionResult, ProofStep } from '../lib/verify.js';

type Props = { entry: Entry };

export function ProofViewer({ entry }: Props) {
  const [proof,  setProof]  = useState<InclusionProof | null>(null);
  const [result, setResult] = useState<InclusionResult | null>(null);
  const [status, setStatus] = useState<VerifyStatus>('idle');
  const [error,  setError]  = useState<string | null>(null);

  useEffect(() => {
    setProof(null);
    setResult(null);
    setStatus('verifying');
    setError(null);

    const enc = new TextEncoder();

    api.proof(entry.seq)
      .then(async (p) => {
        setProof(p);
        const res = await verifyInclusion(p, enc.encode(entry.data));
        setResult(res);
        setStatus(res.ok ? 'verified' : 'failed');
      })
      .catch(e => {
        setError(String(e));
        setStatus('failed');
      });
  }, [entry.seq, entry.data]);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-400 uppercase tracking-wider">Inclusion Proof</span>
        <Badge status={status} />
      </div>

      {error && <p className="text-xs text-accent-red">{error}</p>}

      {proof && (
        <div className="text-xs text-slate-400 space-y-1">
          <p>Tree size at proof: <span className="text-slate-200">{proof.tree_size.toLocaleString()}</span></p>
          <p>Leaf index: <span className="text-slate-200">{proof.leaf_index}</span></p>
          <p>Path length: <span className="text-slate-200">{proof.proof.length} hashes</span></p>
        </div>
      )}

      {result && result.steps.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs text-slate-400 uppercase tracking-wider mb-1">Merkle Path</p>
          {result.steps.map((step, i) => (
            <MerkleStep key={i} step={step} index={i} />
          ))}
          {result.ok ? (
            <div className="mt-2 flex items-center gap-2 text-xs text-accent-green">
              <span>✓</span>
              <span>Computed root matches STH root</span>
            </div>
          ) : (
            <div className="mt-2 text-xs text-accent-red">
              {'reason' in result && <span>✗ {result.reason}</span>}
            </div>
          )}
        </div>
      )}

      {proof && (
        <details className="mt-2">
          <summary className="text-xs text-slate-500 cursor-pointer hover:text-slate-300">Raw proof data</summary>
          <pre className="mt-2 text-[10px] text-slate-400 bg-surface-0 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">
            {JSON.stringify(proof, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}

function MerkleStep({ step, index }: { step: ProofStep; index: number }) {
  return (
    <div className="bg-surface-0 rounded p-2 text-[11px] font-mono space-y-0.5">
      <div className="flex items-center gap-2">
        <span className="text-slate-500 w-4 text-right">{index + 1}</span>
        <span className={clsx(
          'rounded px-1 py-0 text-[10px]',
          step.direction === 'left'
            ? 'bg-accent-purple/10 text-accent-purple'
            : 'bg-accent-amber/10  text-accent-amber',
        )}>
          {step.direction === 'left' ? '← L' : 'R →'}
        </span>
        <span className="text-slate-500">sibling</span>
        <span className="text-slate-300 truncate">{step.sibling.slice(0, 24)}…</span>
      </div>
      <div className="pl-10 text-slate-500">
        → <span className="text-slate-300">{step.running.slice(0, 24)}…</span>
      </div>
    </div>
  );
}
