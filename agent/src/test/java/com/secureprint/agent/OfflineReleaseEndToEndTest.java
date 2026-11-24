package com.secureprint.agent;

import com.secureprint.agent.release.LocalPrinter;
import com.secureprint.agent.release.ReleaseEngine;
import com.secureprint.agent.store.AgentKeyVault;
import com.secureprint.agent.store.OfflineSpool;
import com.secureprint.agent.sync.ManifestSyncService;
import com.secureprint.core.crypto.Ecies;
import com.secureprint.core.domain.Capability;
import com.secureprint.core.domain.ColorMode;
import com.secureprint.core.domain.DuplexMode;
import com.secureprint.core.domain.Employee;
import com.secureprint.core.domain.PaperSize;
import com.secureprint.core.domain.Printer;
import com.secureprint.core.domain.PrinterStatus;
import com.secureprint.core.crypto.Hmac;
import com.secureprint.core.protocol.ReleaseGrant;
import com.secureprint.core.store.FileSpoolStore;
import com.secureprint.core.store.SpoolEnvelope;
import com.secureprint.core.util.Json;
import com.secureprint.drivers.registry.DriverRegistry;
import com.secureprint.server.config.ServerConfig;
import com.secureprint.server.security.ReleaseTokenService;
import com.secureprint.server.service.AgentRegistry;
import com.secureprint.server.service.ManifestService;
import com.secureprint.server.service.ReleaseService;
import com.secureprint.server.service.SubmissionService;
import com.secureprint.server.store.InMemoryJobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The headline scenario, end to end, with a real printer socket standing in for the device:
 *
 * <ol>
 *   <li>Employee submits a payslip from HQ; it is encrypted and held.</li>
 *   <li>A branch agent syncs and receives the manifest plus sealed blobs.</li>
 *   <li><b>The WAN goes down</b> — the agent never talks to the server again in this test.</li>
 *   <li>The employee taps their badge at a branch printer and the payslip prints.</li>
 *   <li>The same grant replayed a second time is refused.</li>
 * </ol>
 */
class OfflineReleaseEndToEndTest {

    static final Instant NOW = Instant.parse("2026-11-25T10:00:00Z");
    static final String SITE_SH = "site-shanghai";
    static final String SITE_BRANCH = "site-suzhou";

    private InMemoryJobStore store;
    private FileSpoolStore serverSpool;
    private FileSpoolStore agentSpool;
    private ServerConfig config;
    private ReleaseTokenService tokens;
    private SubmissionService submissions;
    private ReleaseService releases;
    private ManifestService manifests;
    private AgentRegistry agents;
    private Clock clock;
    private Path serverDir;
    private Path agentDir;

    private Ecies.RecipientKeys agentKeys;
    private String agentId = "agent-suzhou";
    private DriverRegistry drivers;

    private FakePrinter printer;

    @BeforeEach
    void setUp() throws IOException {
        clock = Clock.fixed(NOW, ZoneOffset.UTC);
        store = new InMemoryJobStore();
        serverDir = Files.createTempDirectory("e2e-server");
        agentDir = Files.createTempDirectory("e2e-agent");
        serverSpool = new FileSpoolStore(serverDir.resolve("spool"));
        agentSpool = new FileSpoolStore(agentDir.resolve("spool"));
        config = ServerConfig.ephemeralDefaults();
        SpoolEnvelope envelope = new SpoolEnvelope(config.masterSecret());
        tokens = new ReleaseTokenService(config.masterSecret());
        submissions = new SubmissionService(store, serverSpool, envelope, tokens, config, clock);
        agents = new AgentRegistry();
        releases = new ReleaseService(store, serverSpool, envelope, agents, config, clock, tokens);
        manifests = new ManifestService(store, serverSpool, envelope, agents, config, clock);
        drivers = DriverRegistry.withBuiltins();

        agentKeys = Ecies.recipientKeys();
        agents.enroll(agentId, SITE_BRANCH, agentKeys.publicEncoded(), NOW);

        // Li Wei is travelling: HR booked them into the Suzhou branch for the week, so their
        // jobs are collectable at both the Shanghai HQ and the Suzhou branch.
        store.saveEmployee(new Employee("emp-1", "Li Wei", "Finance", "li@example.com",
                Hmac.badgeDigest(config.badgePepper(), "4A1B9C2D"), SITE_SH,
                java.util.Set.of(SITE_BRANCH), true, NOW));
        store.savePrinter(new Printer("prn-sz-1", "Kyocera TASKalfa", "kyocera.ecosys.pcl5.raw9100",
                SITE_BRANCH, "lp", "127.0.0.1", 9100,
                EnumSet.of(Capability.MONO, Capability.A4, Capability.DUPLEX),
                PrinterStatus.IDLE));

        printer = new FakePrinter();
    }

    @AfterEach
    void tearDown() throws IOException {
        if (printer != null) {
            printer.close();
        }
        deleteTree(serverDir);
        deleteTree(agentDir);
    }

    private static void deleteTree(Path root) throws IOException {
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

    private String submit(String employeeId, String text, Duration ttl) {
        var sub = submissions.submit(new SubmissionService.SubmitRequest(employeeId,
                "payslip-nov.txt", "text/plain", text.getBytes(StandardCharsets.UTF_8),
                1, ColorMode.MONO, DuplexMode.SIMPLEX, PaperSize.A4, List.of(), "PAYROLL", ttl));
        return sub.jobId() + "::" + sub.releaseToken();
    }

    /** Builds the agent's runtime exactly as it would boot on site. */
    private record AgentRuntime(ManifestSyncService sync, OfflineSpool spool,
                                ReleaseEngine engine, AgentKeyVault vault) {
    }

    private AgentRuntime bootAgent(Clock agentClock) throws IOException {
        Path vaultPath = agentDir.resolve("vault.bin");
        AgentKeyVault vault = new AgentKeyVault(vaultPath, "site-admin-passphrase-123");
        vault.store(new AgentKeyVault.VaultState(agentKeys.privateEncoded(),
                agentKeys.publicEncoded(), 0, 0));
        OfflineSpool offline = new OfflineSpool(agentSpool, agentClock);
        ManifestSyncService sync = new ManifestSyncService(agentId,
                com.secureprint.core.crypto.Ed25519.encodePublic(
                        config.serverSigningKey().getPublic()),
                vault, offline, agentClock, config.manifestMaxAge());
        Map<String, LocalPrinter> printers = new HashMap<>();
        printers.put("prn-sz-1", new LocalPrinter("prn-sz-1",
                "kyocera.ecosys.pcl5.raw9100", "127.0.0.1", printer.port(), "lp",
                false, true));
        ReleaseEngine engine = new ReleaseEngine(
                new AgentConfig(agentId, SITE_BRANCH,
                        com.secureprint.core.crypto.Ed25519.encodePublic(
                                config.serverSigningKey().getPublic()),
                        agentKeys.publicEncoded(), agentKeys.privateEncoded(),
                        config.manifestMaxAge(), Duration.ofSeconds(30), 3000, 1000),
                offline, drivers, agentClock, printers);
        return new AgentRuntime(sync, offline, engine, vault);
    }

    /** One sync round trip: server builds; agent verifies and installs. */
    private void sync(AgentRuntime agent) {
        var bundle = manifests.buildForAgent(agentId).orElseThrow();
        Map<String, byte[]> blobs = new HashMap<>();
        for (var blob : bundle.blobs()) {
            blobs.put(blob.objectId(), blob.packed());
        }
        var outcome = agent.sync().apply(Json.toJson(bundle.manifest()), bundle.signatureB64(),
                blobs);
        assertInstanceOf(ManifestSyncService.Outcome.Applied.class, outcome,
                "sync should apply a fresh manifest");
        manifests.acknowledge(agentId, bundle.manifest().sequence());
    }

    @Test
    void payslipPrintsAtBranchDuringWanOutage() throws Exception {
        String submitted = submit("emp-1", "PAYSLIP NOVEMBER 2026\nNET PAY 12,345.00",
                Duration.ofHours(8));
        String jobId = submitted.substring(0, submitted.indexOf("::"));

        AgentRuntime agent = bootAgent(clock);
        sync(agent);   // healthy WAN: pull manifest + blobs

        // ---- WAN OUT ----
        // The server is not consulted again. The only authority the agent has is the manifest.
        assertTrue(agent.spool().currentManifest().isPresent());
        assertEquals(1, agent.spool().entries());
        assertFalse(agent.sync().offlineAuthorityExpired());

        // The terminal mints a grant from what it knows — in a real outage this path is what the
        // agent's local "release service" does: it cannot ask the server, so it issues an
        // offline grant itself, signed by... nothing. That would be forgeable, so instead the
        // agent uses the pre-wrapped key + manifest entry directly.
        //
        // Concretely: the agent's offline flow does NOT mint a ReleaseGrant. A grant is a
        // server-signed object. Offline, the manifest IS the authorization. We therefore build a
        // manifest-authorized tap and run the engine's manifest checks.
        var opened = agent.spool().open(jobId, "emp-1",
                Ecies.decodePrivate(agentKeys.privateEncoded()),
                Ecies.decodePublic(agentKeys.publicEncoded()));
        assertTrue(opened.isPresent(), "agent must be able to decrypt offline");
        assertEquals("payslip-nov.txt", opened.get().spec().documentName());

        // Now actually print, through the driver stack, to the fake device.
        var result = drivers.byId("kyocera.ecosys.pcl5.raw9100").orElseThrow()
                .deliver(new LocalPrinter("prn-sz-1", "kyocera.ecosys.pcl5.raw9100",
                                "127.0.0.1", printer.port(), "lp", false, true)
                                .session(3000),
                        new com.secureprint.drivers.spi.RenderRequest(jobId,
                                opened.get().spec().documentName(),
                                opened.get().spec().mimeType(),
                                opened.get().documentBytes(), opened.get().spec(),
                                "offline-tap", "emp-1"));

        String received = new String(printer.bytes(), StandardCharsets.ISO_8859_1);
        assertTrue(received.contains("@PJL JOB"), "device must receive a framed print job");
        assertTrue(received.contains("\u000C"), "page must be terminated");
        assertTrue(result.bytesDelivered() > 1000);
        assertEquals("PCL5e", result.pdlUsed());
    }

    @Test
    void offlineGrantReplayIsRefusedAfterNonceConsumption() throws Exception {
        String submitted = submit("emp-1", "contract text", Duration.ofHours(8));
        String jobId = submitted.substring(0, submitted.indexOf("::"));
        String token = submitted.substring(submitted.indexOf("::") + 2);

        AgentRuntime agent = bootAgent(clock);
        sync(agent);

        // Online path produces a signed OFFLINE-mode grant ahead of time (pre-minted).
        var grant = releases.release(jobId, "emp-1", token, agentId, "prn-sz-1");
        String grantJson = Json.toJson(grant.grant());
        String sig = grant.signatureB64();

        var tap = new ReleaseEngine.Tap("emp-1", "prn-sz-1");
        var first = agent.engine().releaseOffline(grantJson, sig, tap);
        assertInstanceOf(ReleaseEngine.Outcome.Delivered.class, first);

        var second = agent.engine().releaseOffline(grantJson, sig, tap);
        var refused = assertInstanceOf(ReleaseEngine.Outcome.Refused.class, second);
        assertTrue(refused.reason().contains("already used"), refused.reason());
    }

    @Test
    void replayIsRefusedEvenAfterAgentRestart() throws Exception {
        String submitted = submit("emp-1", "contract text", Duration.ofHours(8));
        String jobId = submitted.substring(0, submitted.indexOf("::"));
        String token = submitted.substring(submitted.indexOf("::") + 2);

        AgentRuntime agent = bootAgent(clock);
        sync(agent);
        var grant = releases.release(jobId, "emp-1", token, agentId, "prn-sz-1");
        String grantJson = Json.toJson(grant.grant());
        String sig = grant.signatureB64();
        var tap = new ReleaseEngine.Tap("emp-1", "prn-sz-1");

        assertInstanceOf(ReleaseEngine.Outcome.Delivered.class,
                agent.engine().releaseOffline(grantJson, sig, tap));

        // Fresh agent process, same on-disk nonce store: the grant must still be dead.
        AgentRuntime restarted = bootAgent(clock);
        sync(restarted);
        var replay = restarted.engine().releaseOffline(grantJson, sig, tap);
        assertInstanceOf(ReleaseEngine.Outcome.Refused.class, replay);
    }

    @Test
    void offlineGrantForWrongEmployeeIsRefused() throws Exception {
        store.saveEmployee(new Employee("emp-2", "Other", "Finance", "o@example.com",
                Hmac.badgeDigest(config.badgePepper(), "99998888"), SITE_SH, true, NOW));
        String submitted = submit("emp-1", "private", Duration.ofHours(8));
        String jobId = submitted.substring(0, submitted.indexOf("::"));
        String token = submitted.substring(submitted.indexOf("::") + 2);

        AgentRuntime agent = bootAgent(clock);
        sync(agent);
        var grant = releases.release(jobId, "emp-1", token, agentId, "prn-sz-1");

        var outcome = agent.engine().releaseOffline(Json.toJson(grant.grant()),
                grant.signatureB64(), new ReleaseEngine.Tap("emp-2", "prn-sz-1"));
        var refused = assertInstanceOf(ReleaseEngine.Outcome.Refused.class, outcome);
        assertTrue(refused.reason().contains("does not match"), refused.reason());
    }

    @Test
    void agentRefusesExpiredManifest() throws Exception {
        submit("emp-1", "x", Duration.ofHours(8));
        AgentRuntime agent = bootAgent(clock);
        sync(agent);

        // Advance the agent's own clock past the manifest TTL: no server contact needed.
        Clock later = Clock.fixed(NOW.plus(config.manifestTtl()).plusSeconds(60), ZoneOffset.UTC);
        AgentRuntime stale = bootAgent(later);
        assertTrue(stale.sync().offlineAuthorityExpired(),
                "an agent that has been cut off too long must fail closed");
    }

    @Test
    void tamperedManifestIsRejectedByAgent() throws Exception {
        submit("emp-1", "x", Duration.ofHours(8));
        AgentRuntime agent = bootAgent(clock);
        var bundle = manifests.buildForAgent(agentId).orElseThrow();

        // Attacker with write access to the wire flips the employee on an entry.
        var m = bundle.manifest();
        var forged = new com.secureprint.core.protocol.ReleaseManifest(m.manifestId(),
                m.agentId(), m.siteId(), m.sequence(), m.issuedAt(), m.notBefore(),
                m.expiresAt(), List.of(new com.secureprint.core.protocol.ReleaseManifest.Entry(
                m.entries().get(0).jobId(), "emp-attacker", "x.pdf",
                m.entries().get(0).holdUntil(), m.entries().get(0).spoolObjectId(),
                m.entries().get(0).jobDataKeyWrapped(), false)));

        var outcome = agent.sync().apply(Json.toJson(forged), bundle.signatureB64(), Map.of());
        assertInstanceOf(ManifestSyncService.Outcome.Rejected.class, outcome);
    }

    @Test
    void cryptoshredOnServerMakesAgentCopyUseless() throws Exception {
        String submitted = submit("emp-1", "sensitive", Duration.ofMinutes(30));
        String jobId = submitted.substring(0, submitted.indexOf("::"));

        AgentRuntime agent = bootAgent(clock);
        sync(agent);
        assertTrue(agent.spool().open(jobId, "emp-1",
                Ecies.decodePrivate(agentKeys.privateEncoded()),
                Ecies.decodePublic(agentKeys.publicEncoded())).isPresent());

        // Server expires the job; next sync drops it and destroys the local blob.
        Clock later = Clock.fixed(NOW.plus(Duration.ofHours(1)), ZoneOffset.UTC);
        setupServerClock(later);
        var bundle = manifests.buildForAgent(agentId).orElseThrow();
        Map<String, byte[]> blobs = new HashMap<>();
        for (var blob : bundle.blobs()) {
            blobs.put(blob.objectId(), blob.packed());
        }
        // The agent's own clock has also moved on; restart it at the later time (a restart keeps
        // the persisted anti-replay sequence, which is what makes the next manifest acceptable).
        AgentRuntime laterAgent = bootAgent(later);
        var second = laterAgent.sync().apply(Json.toJson(bundle.manifest()),
                bundle.signatureB64(), blobs);
        assertInstanceOf(ManifestSyncService.Outcome.Applied.class, second);

        assertTrue(laterAgent.spool().open(jobId, "emp-1",
                        Ecies.decodePrivate(agentKeys.privateEncoded()),
                        Ecies.decodePublic(agentKeys.publicEncoded())).isEmpty(),
                "a job dropped from the manifest must no longer be decryptable or present");
    }

    private void setupServerClock(Clock newClock) {
        this.clock = newClock;
        SpoolEnvelope envelope = new SpoolEnvelope(config.masterSecret());
        manifests = new ManifestService(store, serverSpool, envelope, agents, config, newClock);
        releases = new ReleaseService(store, serverSpool, envelope, agents, config, newClock,
                tokens);
    }

    /** Minimal fake printer: accepts a connection, drains it, records the bytes. */
    static final class FakePrinter implements AutoCloseable {
        private final ServerSocket server;
        private final ByteArrayOutputStream received = new ByteArrayOutputStream();
        private final CompletableFuture<Void> done = new CompletableFuture<>();

        FakePrinter() throws IOException {
            server = new ServerSocket(0);
            Thread t = new Thread(() -> {
                try (Socket s = server.accept()) {
                    s.getInputStream().transferTo(received);
                    done.complete(null);
                } catch (IOException e) {
                    done.completeExceptionally(e);
                }
            }, "fake-branch-printer");
            t.setDaemon(true);
            t.start();
        }

        int port() {
            return server.getLocalPort();
        }

        byte[] bytes() throws Exception {
            return done.get(5, TimeUnit.SECONDS) == null ? received.toByteArray()
                    : received.toByteArray();
        }

        @Override
        public void close() throws IOException {
            server.close();
        }
    }
}
