import { clsx } from 'clsx';
import type { VerifyStatus } from '../types.js';

type Props = { status: VerifyStatus; compact?: boolean };

const labels: Record<VerifyStatus, string> = {
  idle:      '—',
  verifying: 'VERIFYING',
  verified:  'VERIFIED',
  failed:    'FAILED',
};

const styles: Record<VerifyStatus, string> = {
  idle:      'bg-surface-3 text-slate-400',
  verifying: 'bg-surface-3 text-accent-amber animate-pulse',
  verified:  'bg-accent-green/10 text-accent-green border border-accent-green/30',
  failed:    'bg-accent-red/10  text-accent-red  border border-accent-red/30',
};

export function Badge({ status, compact = false }: Props) {
  return (
    <span className={clsx(
      'inline-flex items-center rounded px-1.5 font-mono font-semibold tracking-widest',
      compact ? 'text-[10px] py-0.5' : 'text-xs py-1',
      styles[status],
    )}>
      {labels[status]}
    </span>
  );
}
