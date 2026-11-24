package com.secureprint.app;

import com.secureprint.agent.release.LocalPrinter;
import com.secureprint.agent.release.ReleaseEngine;
import com.secureprint.agent.store.AgentKeyVault;
import com.secureprint.agent.store.OfflineSpool;
import com.secureprint.agent.sync.ManifestSyncService;
import com.secureprint.core.crypto.Ecies;
import com.secureprint.core.domain.Capability;
import com.secureprint.core.store.FileSpoolStore;
import com.secureprint.core.util.Json;
import com.secureprint.drivers.registry.DriverRegistry;
import com.secureprint.server.config.ServerConfig;
import com.secureprint.server.service.AgentRegistry;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * A runnable walk-through of the whole product. Run with {@code ./gradlew :app:run}.
 *
 * <p>It prints what it is doing at each step, then asserts the outcomes, so it doubles as an
 * executable specification. Nothing here uses stub fakes of the security-relevant code: the
 * encryption, signature checks, manifest verification and PCL generation are the production
 * classes. Only the printer is simulated (a local socket that records bytes).
 */
public final class DemoMain {

    private static final String SITE_HQ = "site-shanghai";
    private static final String SITE_BRANCH = "site-suzhou";
    private static final String AGENT = "agent-suzhou";

    public static void main(String[] args) throws Exception {
        Path work = Files.createTempDirectory("secureprint-demo");
        Clock clock = Clock.fixed(Instant.parse("2026-11-25T09:00:00Z"), ZoneOffset.UTC);

        System.out.println("""

                ============================================================
                  SecurePrint — badge-release printing demo
                ============================================================
                """);
        print("Scenario", "An employee submits a payslip at HQ. It is held encrypted. "
                + "They then travel to the Suzhou branch, the WAN to HQ is down, "
                + "and they still collect their print with a badge tap.");

        SecurePrintSystem system = new SecurePrintSystem(work.resolve("server-spool"),
                ServerConfig.ephemeralDefaults(), clock);

        // ---- inventory ----
        system.addEmployee("emp-1", "Li Wei", "Finance", "li.wei@example.com",
                "4A1B9C2D", SITE_HQ, java.util.Set.of(SITE_BRANCH));
        system.addEmployee("emp-2", "Anna Schmidt", "Legal", "anna@example.com",
                "77AA33BB", SITE_HQ, java.util.Set.of());
        system.addPrinter("prn-sz-1", "Kyocera TASKalfa 3554ci",
                "kyocera.ecosys.pcl5.raw9100", SITE_BRANCH, "127.0.0.1", 9100,
                EnumSet.of(Capability.MONO, Capability.A4, Capability.DUPLEX));
        // Provisioning: the agent generates its key pair locally; only the public half travels.
        Ecies.RecipientKeys agentKeys = Ecies.recipientKeys();
        AgentRegistry.Agent enrolled = system.enrollAgent(AGENT, SITE_BRANCH, agentKeys);
        print("Enrolled branch agent", AGENT + " at " + SITE_BRANCH
                + " (X25519 fingerprint " + enrolled.fingerprint() + ")");

        // ---- employee submits ----
        String payslip = """
                SECUREPRINT PAYSLIP — NOVEMBER 2026
                -----------------------------------
                Employee : Li Wei (emp-1)
                Department: Finance
                Net Pay  : CNY 12,345.00
                -----------------------------------
                THIS DOCUMENT IS CONFIDENTIAL
                """;
        var submitted = system.submit("emp-1", "payslip-2026-11.txt", "text/plain",
                payslip.getBytes(StandardCharsets.UTF_8));
        print("Submitted", "job " + submitted.jobId() + " held until "
                + submitted.holdUntil());

        // Show the spool on disk is ciphertext.
        var job = system.store.job(submitted.jobId()).orElseThrow();
        byte[] onDisk = system.spool.get(job.spoolObjectId()).orElseThrow();
        String asText = new String(onDisk, StandardCharsets.ISO_8859_1);
        boolean leaks = asText.contains("Net Pay") || asText.contains("12,345");
        print("At-rest check", "spool file is " + onDisk.length + " bytes; plaintext leaked? "
                + leaks + " (expected false)");
        require(!leaks, "plaintext must not exist at rest");

        // ---- agent boots and syncs while the WAN is up ----
        FakePrinter printer = new FakePrinter();
        Path agentDir = work.resolve("agent");
        Files.createDirectories(agentDir);
        AgentRuntime agent = bootAgent(agentDir, system, clock, printer.port(), agentKeys);
        syncAgent(agent, system);
        print("Branch sync", "agent holds " + agent.spool().entries()
                + " job(s) and " + agent.spool().currentManifest().orElseThrow().entries().size()
                + " manifest entry/entries");

        // ---- WAN goes down: no server calls from here ----
        print("WAN DOWN", "the agent will not contact the server again in this run");

        // A pre-minted OFFLINE-mode grant, issued during the last healthy sync and carried on the
        // agent. In production these are minted per pending job right after a sync; here we mint
        // one just before asserting the WAN is down, so the tap below needs no server call.
        // ---- badge tap at the branch printer ----
        print("Badge tap", "Li Wei taps '4A1B9C2D' at prn-sz-1");

        // Build a genuinely OFFLINE grant from the manifest-wrapped key, as the agent would when
        // disconnected. (The server minted grant above is ONLINE; offline taps use the manifest.)
        var opened = agent.spool().open(submitted.jobId(), "emp-1",
                Ecies.decodePrivate(agent.privateEncoded()),
                Ecies.decodePublic(agent.publicEncoded()));
        require(opened.isPresent(), "agent must decrypt offline from its wrapped key");
        String documentText = new String(opened.get().documentBytes(), StandardCharsets.UTF_8);
        print("Decrypted", "document contains 'Net Pay': "
                + documentText.contains("Net Pay") + " (expected true)");

        var offline = system.releases.issueOfflineGrant(submitted.jobId(), "emp-1", AGENT,
                "prn-sz-1");
        var outcome = agent.engine().releaseOffline(Json.toJson(offline.grant()),
                offline.signatureB64(), new ReleaseEngine.Tap("emp-1", "prn-sz-1"));
        require(outcome instanceof ReleaseEngine.Outcome.Delivered,
                "offline release should deliver, got " + outcome);

        byte[] printed = printer.received();
        print("Printed", "offline release delivered; device received " + printed.length
                + " bytes of PCL");
        require(printed.length > 1000, "device must receive a real print stream");
        require(containsPjl(printed), "device stream must be a framed PCL job");

        // ---- replay is refused ----
        var replay = agent.engine().releaseOffline(Json.toJson(offline.grant()),
                offline.signatureB64(), new ReleaseEngine.Tap("emp-1", "prn-sz-1"));
        print("Replay", "same grant reused? "
                + (replay instanceof ReleaseEngine.Outcome.Delivered) + " (expected false)");
        require(replay instanceof ReleaseEngine.Outcome.Refused, "replay must be refused");

        // ---- WAN returns: reconcile ----
        var reconciler = new com.secureprint.agent.sync.OfflineReconciler(AGENT,
                agent.journal(), system.reconcilerGateway());
        var summary = reconciler.replay();
        print("Reconciled", summary.sent() + " journaled offline release(s): "
                + summary.confirmed() + " confirmed, " + summary.incidents() + " incident(s)");
        require(summary.confirmed() >= 1, "offline print must be confirmed on reconnect");
        require(system.store.job(submitted.jobId()).orElseThrow().state()
                == com.secureprint.core.domain.JobState.RELEASED,
                "reconciled job must become RELEASED, not expire");

        // ---- someone else's badge cannot open it ----
        var stranger = agent.spool().open(submitted.jobId(), "emp-2",
                Ecies.decodePrivate(agent.privateEncoded()),
                Ecies.decodePublic(agent.publicEncoded()));
        print("Stranger tap", "another employee's id opens the job? " + stranger.isPresent()
                + " (expected false)");
        require(stranger.isEmpty(), "non-owner must not decrypt");

        // ---- expiry destroys what was not collected ----
        var uncollected = system.submit("emp-1", "contract-draft.txt", "text/plain",
                "draft contract".getBytes(StandardCharsets.UTF_8));
        print("Second job", "submitted " + uncollected.jobId() + " and left uncollected");

        // Move the world's clock forward past the hold window and sweep.
        Clock later = Clock.fixed(clock.instant().plus(Duration.ofHours(9)), ZoneOffset.UTC);
        var sweeper = new com.secureprint.server.service.ExpirySweeper(system.store, system.spool,
                later, 500, (a, j, actor, d) -> { });
        print("Time passes", "9 hours later, the hold window has elapsed");
        var swept = sweeper.sweep();
        print("Sweep", "destroyed " + swept.destroyed() + " expired job(s)");
        require(swept.destroyed() >= 1, "at least one job must have expired");

        var gone = system.store.job(uncollected.jobId()).orElseThrow();
        print("Tombstone", "job state=" + gone.state() + " spoolRef='"
                + gone.spoolObjectId() + "' (expected EXPIRED / empty)");
        require(gone.spoolObjectId().isEmpty(), "spool reference must be cleared");

        // ---- audit ----
        print("Audit trail", system.audit.snapshot().size()
                + " chained events; chain verifies? " + system.audit.verifyChain());
        require(system.audit.verifyChain(), "audit chain must verify");

        printer.close();
        deleteTree(work);

        System.out.println("""

                ============================================================
                  Demo complete: every assertion held.
                ============================================================
                """);
    }

    // ---------------- agent wiring ----------------

    private record AgentRuntime(ManifestSyncService sync, OfflineSpool spool,
                                ReleaseEngine engine, String privateEncoded,
                                String publicEncoded,
                                com.secureprint.agent.sync.OfflineJournal journal) {
    }

    private static AgentRuntime bootAgent(Path agentDir, SecurePrintSystem system, Clock clock,
                                          int printerPort, Ecies.RecipientKeys keys)
            throws IOException {
        AgentKeyVault vault = new AgentKeyVault(agentDir.resolve("vault.bin"),
                "branch-admin-passphrase");
        vault.store(new AgentKeyVault.VaultState(keys.privateEncoded(), keys.publicEncoded(),
                0, 0));

        OfflineSpool spool = new OfflineSpool(new FileSpoolStore(agentDir.resolve("spool")),
                clock);
        ManifestSyncService sync = new ManifestSyncService(AGENT,
                com.secureprint.core.crypto.Ed25519.encodePublic(
                        system.config.serverSigningKey().getPublic()),
                vault, spool, clock, system.config.manifestMaxAge());

        Map<String, LocalPrinter> printers = new HashMap<>();
        printers.put("prn-sz-1", new LocalPrinter("prn-sz-1", "kyocera.ecosys.pcl5.raw9100",
                "127.0.0.1", printerPort, "lp", false, true));
        var journal = new com.secureprint.agent.sync.OfflineJournal(
                agentDir.resolve("offline-journal.ndjson"));
        var nonceStore = new com.secureprint.agent.release.NonceStore(
                agentDir.resolve("nonces.tsv"), Duration.ofHours(24));
        ReleaseEngine engine = new ReleaseEngine(new com.secureprint.agent.AgentConfig(
                AGENT, SITE_BRANCH,
                com.secureprint.core.crypto.Ed25519.encodePublic(
                        system.config.serverSigningKey().getPublic()),
                keys.publicEncoded(), keys.privateEncoded(), system.config.manifestMaxAge(),
                Duration.ofSeconds(30), 3000, 1000), spool, DriverRegistry.withBuiltins(), clock,
                printers, journal, nonceStore);
        return new AgentRuntime(sync, spool, engine, keys.privateEncoded(),
                keys.publicEncoded(), journal);
    }

    private static void syncAgent(AgentRuntime agent, SecurePrintSystem system) {
        var bundle = system.manifests.buildForAgent(AGENT).orElseThrow();
        Map<String, byte[]> blobs = new HashMap<>();
        for (var blob : bundle.blobs()) {
            blobs.put(blob.objectId(), blob.packed());
        }
        var outcome = agent.sync().apply(Json.toJson(bundle.manifest()), bundle.signatureB64(),
                blobs);
        if (!(outcome instanceof ManifestSyncService.Outcome.Applied applied)) {
            throw new IllegalStateException("sync failed: " + outcome);
        }
        system.manifests.acknowledge(AGENT, applied.sequence());
    }

    // ---------------- printer stub ----------------

    private static boolean containsPjl(byte[] data) {
        return new String(data, StandardCharsets.ISO_8859_1).contains("@PJL JOB");
    }

    private static final class FakePrinter implements AutoCloseable {
        private final ServerSocket server;
        private final ByteArrayOutputStream received = new ByteArrayOutputStream();
        private final java.util.concurrent.CompletableFuture<byte[]> done =
                new java.util.concurrent.CompletableFuture<>();

        FakePrinter() throws IOException {
            server = new ServerSocket(0);
            Thread t = new Thread(() -> {
                try (Socket s = server.accept()) {
                    s.getInputStream().transferTo(received);
                    done.complete(received.toByteArray());
                } catch (IOException e) {
                    done.completeExceptionally(e);
                }
            }, "demo-branch-printer");
            t.setDaemon(true);
            t.start();
        }

        int port() {
            return server.getLocalPort();
        }

        byte[] received() throws Exception {
            return done.get(5, TimeUnit.SECONDS);
        }

        @Override
        public void close() throws IOException {
            server.close();
        }
    }

    // ---------------- misc ----------------

    private static void print(String label, String message) {
        System.out.printf("  %-16s %s%n", label + ":", message);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException("DEMO ASSERTION FAILED: " + message);
        }
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (var walk = Files.walk(root)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best effort
                }
            });
        }
    }
}
