package io.settled.sdk;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * End-to-end integration tests for the Java SDK.
 *
 * Boots a real settled-server subprocess on an ephemeral port, talks to
 * it via SettledClient over real gRPC, and verifies proofs locally using
 * the Java Verifier.
 *
 * Skipped automatically when the server binary cannot be found at
 * target/{release,debug}/settled-server relative to the repo root.
 *
 * Run only:  ./gradlew :java:test --tests "*.IntegrationTest"
 * Skip:      ./gradlew :java:test -x IntegrationTest
 */
class IntegrationTest {

    private Process serverProcess;
    private SettledClient client;

    // ── Harness ───────────────────────────────────────────────────────────────

    private static Path findServerBinary() {
        Path repoRoot = Paths.get(System.getProperty("user.dir")).resolve("../..").normalize();
        for (String rel : List.of("target/release/settled-server", "target/debug/settled-server")) {
            Path p = repoRoot.resolve(rel);
            if (p.toFile().exists() && p.toFile().canExecute()) return p;
        }
        return null;
    }

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            s.setReuseAddress(true);
            return s.getLocalPort();
        }
    }

    private static void waitForPort(int port, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            try (Socket ignored = new Socket("127.0.0.1", port)) {
                return;
            } catch (IOException ignored) {
                Thread.sleep(100);
            }
        }
        throw new RuntimeException("Server did not start on port " + port + " within " + timeoutMs + "ms");
    }

    @BeforeEach
    void startServer() throws Exception {
        Path binary = findServerBinary();
        assumeTrue(binary != null,
                "settled-server binary not found; run `cargo build -p settled-server` from the repo root");

        int grpcPort  = freePort();
        int adminPort = freePort();
        Path dataDir  = Files.createTempDirectory("settled-integration-");

        serverProcess = new ProcessBuilder(
                binary.toString(),
                "--data-dir",      dataDir.toString(),
                "--listen",        "127.0.0.1:" + grpcPort,
                "--admin-listen",  "127.0.0.1:" + adminPort,
                "--sth-interval-secs", "1"
        ).redirectErrorStream(true).start();

        waitForPort(grpcPort, 15_000);
        client = new SettledClient("127.0.0.1:" + grpcPort);
    }

    @AfterEach
    void stopServer() {
        if (client != null) client.close();
        if (serverProcess != null) {
            serverProcess.destroy();
            try {
                if (!serverProcess.waitFor(5, TimeUnit.SECONDS)) serverProcess.destroyForcibly();
            } catch (InterruptedException e) {
                serverProcess.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
    }

    private SettledClient.Sth waitForSth(long minSize) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                SettledClient.Sth sth = client.getSth(0);
                if (Long.compareUnsigned(sth.treeSize(), minSize) >= 0) return sth;
            } catch (Exception ignored) {}
            Thread.sleep(100);
        }
        throw new RuntimeException("No STH covering " + minSize + " entries within 5s");
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    @Test
    void appendAndGetRoundTrip() {
        for (int i = 0; i < 20; i++) {
            SettledClient.AppendResult res = client.append("k".getBytes(), ("d-" + i).getBytes());
            assertEquals(i, res.seq(), "seq must be monotonic from 0");
        }
        for (int i = 0; i < 20; i++) {
            SettledClient.Entry e = client.get(i);
            assertEquals(i, e.seq());
            assertArrayEquals(("d-" + i).getBytes(), e.data(), "data must round-trip unchanged");
        }
    }

    @Test
    void signedTreeHeadVerifies() throws InterruptedException {
        for (int i = 0; i < 5; i++) {
            client.append("k".getBytes(), ("sth-" + i).getBytes());
        }
        SettledClient.Sth sth = waitForSth(5);

        assertTrue(
                Verifier.verifyTreeHead(sth.treeSize(), sth.rootHash(), sth.timestampNs(), sth.signature(), sth.publicKey()),
                "STH signature must verify with the embedded public key"
        );

        byte[] tampered = sth.rootHash().clone();
        tampered[0] ^= 1;
        assertFalse(
                Verifier.verifyTreeHead(sth.treeSize(), tampered, sth.timestampNs(), sth.signature(), sth.publicKey()),
                "tampered root must fail verification"
        );
    }

    @Test
    void inclusionProofsVerify() throws InterruptedException {
        final int N = 15;
        byte[][] leafHashes = new byte[N][];
        for (int i = 0; i < N; i++) {
            SettledClient.AppendResult res = client.append("k".getBytes(), ("e-" + i).getBytes());
            leafHashes[i] = res.leafHash();
        }
        SettledClient.Sth sth = waitForSth(N);

        for (int i = 0; i < N; i++) {
            SettledClient.InclusionProofResult p = client.inclusionProof(i, sth.treeSize());
            assertTrue(
                    Verifier.verifyInclusion(leafHashes[i], p.leafIndex(), sth.treeSize(), p.proof(), sth.rootHash()),
                    "inclusion proof for seq " + i + " must verify"
            );
        }
    }

    @Test
    void consistencyProofVerifies() throws InterruptedException {
        for (int i = 0; i < 10; i++) {
            client.append("k".getBytes(), ("a-" + i).getBytes());
        }
        SettledClient.Sth sthOld = waitForSth(10);

        for (int i = 10; i < 25; i++) {
            client.append("k".getBytes(), ("b-" + i).getBytes());
        }
        SettledClient.Sth sthNew = waitForSth(25);

        SettledClient.ConsistencyProofResult cp = client.consistencyProof(sthOld.treeSize(), sthNew.treeSize());
        assertTrue(
                Verifier.verifyConsistency(cp.oldSize(), cp.newSize(), cp.proof(), sthOld.rootHash(), sthNew.rootHash()),
                "consistency proof between two real STHs must verify"
        );
    }
}
