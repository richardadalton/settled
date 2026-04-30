/**
 * Test harness: boot a real `settled-server` subprocess for integration tests.
 *
 * Mirrors the pattern established by sdks/python/tests/test_integration.py.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as net from 'node:net';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../../..');
const SERVER_BIN_DEBUG = path.join(REPO_ROOT, 'target', 'debug', 'settled-server');
const SERVER_BIN_RELEASE = path.join(REPO_ROOT, 'target', 'release', 'settled-server');

export function findServerBinary(): string | null {
  if (existsSync(SERVER_BIN_RELEASE)) return SERVER_BIN_RELEASE;
  if (existsSync(SERVER_BIN_DEBUG)) return SERVER_BIN_DEBUG;
  return null;
}

function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      if (addr && typeof addr === 'object') {
        const port = addr.port;
        srv.close(() => resolve(port));
      } else {
        srv.close(() => reject(new Error('no port assigned')));
      }
    });
  });
}

function waitForPort(host: string, port: number, timeoutMs = 15000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryConnect = () => {
      const socket = net.createConnection({ host, port, timeout: 200 });
      socket.once('connect', () => {
        socket.destroy();
        resolve();
      });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) {
          reject(new Error(`server did not accept connections on ${host}:${port} within ${timeoutMs}ms`));
        } else {
          setTimeout(tryConnect, 100);
        }
      });
    };
    tryConnect();
  });
}

export interface LiveServer {
  address: string;
  stop: () => Promise<void>;
}

/**
 * Spawn settled-server on an ephemeral port, backed by a fresh tempdir.
 * Caller must invoke ``stop()`` to clean up.
 */
export async function startServer(): Promise<LiveServer> {
  const binary = findServerBinary();
  if (!binary) {
    throw new Error(
      `settled-server binary not found at ${SERVER_BIN_DEBUG} or ${SERVER_BIN_RELEASE}.\n` +
      `Run \`cargo build -p settled-server\` from the repo root, then re-run the tests.`,
    );
  }

  const grpcPort = await findFreePort();
  const adminPort = await findFreePort();
  const dataDir = mkdtempSync(path.join(tmpdir(), 'settled-it-'));

  const proc: ChildProcess = spawn(
    binary,
    [
      '--data-dir', dataDir,
      '--listen', `127.0.0.1:${grpcPort}`,
      '--admin-listen', `127.0.0.1:${adminPort}`,
      '--sth-interval-secs', '1',
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );

  const stderrChunks: Buffer[] = [];
  proc.stderr?.on('data', (c: Buffer) => stderrChunks.push(c));

  try {
    await waitForPort('127.0.0.1', grpcPort);
  } catch (e) {
    proc.kill('SIGKILL');
    const stderr = Buffer.concat(stderrChunks).toString('utf-8');
    rmSync(dataDir, { recursive: true, force: true });
    throw new Error(`${(e as Error).message}\nserver stderr:\n${stderr}`);
  }

  const stop = async (): Promise<void> => {
    if (!proc.killed) {
      proc.kill('SIGTERM');
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          proc.kill('SIGKILL');
          resolve();
        }, 5000);
        proc.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    rmSync(dataDir, { recursive: true, force: true });
  };

  return { address: `127.0.0.1:${grpcPort}`, stop };
}

/** Poll GetSth(0) until an STH covers at least ``minSize`` entries. */
export async function waitForSth<T extends { treeSize: bigint }>(
  fetch: () => Promise<T>,
  minSize: bigint,
  timeoutMs = 5000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const sth = await fetch();
      if (sth.treeSize >= minSize) return sth;
    } catch {
      // STH not yet available; keep polling.
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`no STH covering ${minSize} entries within ${timeoutMs}ms`);
}

