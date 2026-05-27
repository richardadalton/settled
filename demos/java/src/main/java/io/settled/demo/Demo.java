/*
 * Settled Java Demo
 *
 * Usage:
 *   ./gradlew run                                              # append demo entries + show log
 *   ./gradlew run --args='--skip-append'                      # show existing log
 *   ./gradlew run --args='--verify'                           # append + verify STH + inclusion proofs
 *   ./gradlew run --args='--verify --consistency'             # also verify consistency before→after append
 *   ./gradlew run --args='--get 3'                            # look up a single entry by seq
 *   ./gradlew run --args='--get 3 --verify'                   # look up + verify its inclusion proof
 *   ./gradlew run --args='--watch'                            # tail new entries as they arrive
 *   ./gradlew run --args='--watch --verify'                   # tail + verify each new entry
 *   ./gradlew run --args='--host localhost:50051'             # connect to a non-default address
 */
package io.settled.demo;

import io.settled.sdk.SettledClient;
import io.settled.sdk.SettledClient.*;
import io.settled.sdk.Verifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

public class Demo {

    private static final int COL_SEQ  = 4;
    private static final int COL_KEY  = 20;
    private static final int COL_DATA = 20;
    private static final int COL_TIME = 20;
    private static final int COL_HASH = 18;

    private static final String[][] DEMO_ENTRIES = {
        {"user:alice",  "login"},
        {"order:1001",  "created"},
        {"order:1001",  "payment_received"},
        {"order:1001",  "shipped"},
        {"user:bob",    "login"},
        {"order:1002",  "created"},
    };

    public static void main(String[] args) throws Exception {
        String  host        = "localhost:50051";
        boolean skipAppend  = false;
        boolean doVerify    = false;
        boolean doConsistency = false;
        Long    getSeq      = null;
        boolean doWatch     = false;
        double  interval    = 2.0;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--host"         -> host          = args[++i];
                case "--skip-append"  -> skipAppend    = true;
                case "--verify"       -> doVerify      = true;
                case "--consistency"  -> doConsistency = true;
                case "--get"          -> getSeq        = Long.parseLong(args[++i]);
                case "--watch"        -> doWatch       = true;
                case "--interval"     -> interval      = Double.parseDouble(args[++i]);
                default -> { System.err.println("Unknown option: " + args[i]); System.exit(1); }
            }
        }

        System.out.printf("Connecting to %s …%n%n", host);
        try (SettledClient client = new SettledClient(host)) {
            if (doWatch) {
                modeWatch(client, doVerify, interval);
            } else if (getSeq != null) {
                modeGet(client, getSeq, doVerify);
            } else {
                modeDefault(client, doVerify, doConsistency, skipAppend);
            }
        }
    }

    // ── Formatting ─────────────────────────────────────────────────────────────

    private static String fmtTime(long tsNs) {
        Instant instant = Instant.ofEpochSecond(tsNs / 1_000_000_000L, tsNs % 1_000_000_000L);
        String s = instant.toString(); // yyyy-MM-ddTHH:mm:ss.SSSZ
        return s.substring(11, 23) + "Z"; // HH:mm:ss.SSS + Z
    }

    private static String fmtHash(byte[] h) {
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.substring(0, 16) + "…";
    }

    private static String tableHeader(boolean showProof) {
        String h = String.format("%" + COL_SEQ + "s  %-" + COL_KEY + "s  %-" + COL_DATA + "s  %-" + COL_TIME + "s  %-" + COL_HASH + "s",
                "Seq", "Key", "Data", "Time", "Leaf Hash");
        return showProof ? h + "  Proof" : h;
    }

    private static String entryRow(Entry e, String proofCol) {
        String key  = new String(e.key(),  StandardCharsets.UTF_8);
        String data = new String(e.data(), StandardCharsets.UTF_8);
        return String.format("%" + COL_SEQ + "d  %-" + COL_KEY + "s  %-" + COL_DATA + "s  %-" + COL_TIME + "s  %-" + COL_HASH + "s%s",
                e.seq(), key, data, fmtTime(e.timestampNs()), fmtHash(e.leafHash()), proofCol);
    }

    private static void printTable(List<Entry> entries, Map<Long, Boolean> verified) {
        String header = tableHeader(verified != null);
        System.out.println(header);
        System.out.println("-".repeat(header.length()));
        for (Entry e : entries) {
            String proof = "";
            if (verified != null) {
                proof = Boolean.TRUE.equals(verified.get(e.seq())) ? "  OK" : "  FAIL";
            }
            System.out.println(entryRow(e, proof));
        }
    }

    // ── Verification helpers ──────────────────────────────────────────────────

    private static Sth waitForSth(SettledClient client, long minSize) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                Sth sth = client.getSth(0);
                if (Long.compareUnsigned(sth.treeSize(), minSize) >= 0) return sth;
            } catch (Exception ignored) {}
            Thread.sleep(200);
        }
        throw new RuntimeException("No STH covering " + minSize + " entries within 10s");
    }

    private static Sth checkSth(SettledClient client, long minSize) throws InterruptedException {
        Sth sth = waitForSth(client, minSize);
        System.out.print("Verifying STH signature … ");
        boolean ok = Verifier.verifyTreeHead(
                sth.treeSize(), sth.rootHash(), sth.timestampNs(), sth.signature(), sth.publicKey());
        System.out.println(ok ? "OK" : "FAIL");
        if (!ok) System.out.println("  Warning: STH signature invalid — results below may not be trustworthy.");
        return sth;
    }

    private static Map<Long, Boolean> checkInclusions(SettledClient client, List<Entry> entries, Sth sth) {
        int n = entries.size();
        System.out.printf("Verifying inclusion proof%s for %d entr%s … ",
                n == 1 ? "" : "s", n, n == 1 ? "y" : "ies");
        Map<Long, Boolean> results = new LinkedHashMap<>();
        for (Entry e : entries) {
            InclusionProofResult p = client.inclusionProof(e.seq(), sth.treeSize());
            results.put(e.seq(), Verifier.verifyInclusion(
                    e.leafHash(), p.leafIndex(), p.treeSize(), p.proof(), sth.rootHash()));
        }
        long failed = results.values().stream().filter(v -> !v).count();
        System.out.println(failed == 0 ? "all OK" : failed + " FAILED");
        return results;
    }

    private static void checkConsistency(SettledClient client, Sth oldSth, Sth newSth) {
        System.out.printf("Verifying consistency proof  %d → %d … ", oldSth.treeSize(), newSth.treeSize());
        if (oldSth.treeSize() == newSth.treeSize()) {
            System.out.println("nothing to prove (tree unchanged)");
            return;
        }
        ConsistencyProofResult p = client.consistencyProof(oldSth.treeSize(), newSth.treeSize());
        boolean ok = Verifier.verifyConsistency(
                p.oldSize(), p.newSize(), p.proof(), oldSth.rootHash(), newSth.rootHash());
        System.out.println(ok ? "OK" : "FAIL");
    }

    // ── Modes ─────────────────────────────────────────────────────────────────

    private static void modeGet(SettledClient client, long seq, boolean doVerify) throws InterruptedException {
        Entry e;
        try {
            e = client.get(seq);
        } catch (Exception ex) {
            System.err.printf("Error fetching seq %d: %s%n", seq, ex.getMessage());
            return;
        }

        String proofCol = "";
        if (doVerify) {
            Sth sth = checkSth(client, seq + 1);
            InclusionProofResult p = client.inclusionProof(seq, sth.treeSize());
            boolean ok = Verifier.verifyInclusion(
                    e.leafHash(), p.leafIndex(), p.treeSize(), p.proof(), sth.rootHash());
            proofCol = ok ? "  OK" : "  FAIL";
            System.out.println();
        }

        String header = tableHeader(doVerify);
        System.out.println(header);
        System.out.println("-".repeat(header.length()));
        System.out.println(entryRow(e, proofCol));
    }

    private static void modeWatch(SettledClient client, boolean doVerify, double intervalSecs) throws InterruptedException {
        System.out.printf("Watching for new entries (polling every %.0fs) … Ctrl-C to stop.%n%n", intervalSecs);

        long seq = 0;
        try { seq = waitForSth(client, 1).treeSize(); } catch (Exception ignored) {}

        System.out.println(tableHeader(doVerify));
        System.out.println("-".repeat(tableHeader(doVerify).length()));

        Runtime.getRuntime().addShutdownHook(new Thread(() -> System.out.println("\nStopped.")));

        while (!Thread.currentThread().isInterrupted()) {
            Sth sth;
            try { sth = waitForSth(client, 1); } catch (Exception e) {
                Thread.sleep((long) (intervalSecs * 1000));
                continue;
            }
            while (Long.compareUnsigned(seq, sth.treeSize()) < 0) {
                Entry e = client.get(seq);
                String proofCol = "";
                if (doVerify) {
                    InclusionProofResult p = client.inclusionProof(seq, sth.treeSize());
                    boolean ok = Verifier.verifyInclusion(
                            e.leafHash(), p.leafIndex(), p.treeSize(), p.proof(), sth.rootHash());
                    proofCol = ok ? "  OK" : "  FAIL";
                }
                System.out.println(entryRow(e, proofCol));
                seq++;
            }
            Thread.sleep((long) (intervalSecs * 1000));
        }
    }

    private static void modeDefault(SettledClient client, boolean doVerify, boolean doConsistency, boolean skipAppend) throws InterruptedException {
        Sth oldSth = null;
        if (doConsistency) {
            try { oldSth = waitForSth(client, 1); } catch (Exception ignored) {}
        }

        if (!skipAppend) {
            System.out.println("Appending demo entries …");
            for (String[] kv : DEMO_ENTRIES) {
                AppendResult res = client.append(
                        kv[0].getBytes(StandardCharsets.UTF_8),
                        kv[1].getBytes(StandardCharsets.UTF_8));
                System.out.printf("  appended seq=%d  key=%s  data=%s%n", res.seq(), kv[0], kv[1]);
            }
            System.out.println();
        }

        Sth sth;
        try {
            sth = waitForSth(client, 1);
        } catch (Exception e) {
            System.out.println("Log is empty.");
            return;
        }

        System.out.println("Fetching audit trail …\n");
        List<Entry> entries = new ArrayList<>();
        for (long s = 0; s < sth.treeSize(); s++) {
            entries.add(client.get(s));
        }

        Map<Long, Boolean> verified = null;
        if (doVerify) {
            sth = checkSth(client, sth.treeSize());
            verified = checkInclusions(client, entries, sth);
            if (doConsistency && oldSth != null) {
                checkConsistency(client, oldSth, sth);
            }
            System.out.println();
        }

        printTable(entries, verified);
        int n = entries.size();
        System.out.printf("%n%d entr%s in log.%n", n, n == 1 ? "y" : "ies");
    }
}
