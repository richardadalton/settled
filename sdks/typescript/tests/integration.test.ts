/**
 * End-to-end integration tests for the TypeScript SDK.
 *
 * Boots a real `settled-server` subprocess, talks to it via the
 * SettledClient, and verifies proofs locally with the verifier.
 *
 * Skipped automatically when the server binary cannot be found at
 * `target/{debug,release}/settled-server`.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  SettledClient,
  verifyConsistency,
  verifyInclusion,
  verifyTreeHead,
} from '../src/index.js';
import { findServerBinary, startServer, waitForSth, type LiveServer } from './harness.js';

const SERVER_BIN = findServerBinary();
const skipIfNoBinary = SERVER_BIN === null;

describe.skipIf(skipIfNoBinary)('SettledClient ↔ live server', () => {
  let server: LiveServer;
  let client: SettledClient;

  beforeEach(async () => {
    server = await startServer();
    client = new SettledClient(server.address);
    await client.waitForReady(10_000);
  });

  afterEach(async () => {
    client.close();
    await server.stop();
  });

  it('append → get round-trips data unchanged', async () => {
    for (let i = 0; i < 20; i++) {
      const res = await client.append(
        new TextEncoder().encode('k'),
        new TextEncoder().encode(`d-${i}`),
      );
      expect(res.seq).toBe(BigInt(i));
    }

    for (let i = 0; i < 20; i++) {
      const entry = await client.get(BigInt(i));
      expect(entry.seq).toBe(BigInt(i));
      expect(new TextDecoder().decode(entry.data)).toBe(`d-${i}`);
    }
  });

  it('getLatest returns newest-first and defaults n=1', async () => {
    for (let i = 0; i < 10; i++) {
      await client.append(
        new TextEncoder().encode('k'),
        new TextEncoder().encode(`x-${i}`),
      );
    }

    const five = await client.getLatest(5);
    expect(five.map((e) => e.seq)).toEqual([9n, 8n, 7n, 6n, 5n]);
    expect(new TextDecoder().decode(five[0]!.data)).toBe('x-9');

    const single = await client.getLatest();
    expect(single).toHaveLength(1);
    expect(single[0]!.seq).toBe(9n);
  });

  it('signed tree head signature verifies (and fails on tamper)', async () => {
    for (let i = 0; i < 5; i++) {
      await client.append(
        new TextEncoder().encode('k'),
        new TextEncoder().encode(`d-${i}`),
      );
    }

    const sth = await waitForSth(() => client.getSth(0n), 5n);

    expect(verifyTreeHead(sth)).toBe(true);

    // Tampered root must fail.
    const tamperedRoot = new Uint8Array(sth.rootHash);
    tamperedRoot[0] ^= 0x01;
    expect(verifyTreeHead({ ...sth, rootHash: tamperedRoot })).toBe(false);
  });

  it('inclusion proof from server verifies with TS verifier (every entry)', async () => {
    const N = 15;
    const leaves: Uint8Array[] = [];
    for (let i = 0; i < N; i++) {
      const res = await client.append(
        new TextEncoder().encode('k'),
        new TextEncoder().encode(`e-${i}`),
      );
      leaves.push(res.leafHash);
    }

    const sth = await waitForSth(() => client.getSth(0n), BigInt(N));

    for (let i = 0; i < N; i++) {
      const ip = await client.inclusionProof(BigInt(i), sth.treeSize);
      const ok = verifyInclusion(leaves[i]!, BigInt(i), sth.treeSize, ip.proof, sth.rootHash);
      expect(ok, `inclusion proof for seq ${i}`).toBe(true);
    }
  });

  it('consistency proof between two STHs verifies', async () => {
    for (let i = 0; i < 10; i++) {
      await client.append(
        new TextEncoder().encode('k'),
        new TextEncoder().encode(`a-${i}`),
      );
    }
    const sthOld = await waitForSth(() => client.getSth(0n), 10n);

    for (let i = 10; i < 25; i++) {
      await client.append(
        new TextEncoder().encode('k'),
        new TextEncoder().encode(`b-${i}`),
      );
    }
    const sthNew = await waitForSth(() => client.getSth(0n), 25n);

    const cp = await client.consistencyProof(sthOld.treeSize, sthNew.treeSize);
    expect(
      verifyConsistency(
        sthOld.treeSize,
        sthNew.treeSize,
        cp.proof,
        sthOld.rootHash,
        sthNew.rootHash,
      ),
    ).toBe(true);
  });
});

describe.skipIf(!skipIfNoBinary)('integration tests skipped', () => {
  it('settled-server binary not built; run `cargo build -p settled-server`', () => {
    // Informational placeholder so the test report shows why integration
    // tests didn't run.
    expect(skipIfNoBinary).toBe(true);
  });
});

