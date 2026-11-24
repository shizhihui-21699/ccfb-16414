package com.secureprint.server;

import com.secureprint.core.crypto.Ed25519;
import com.secureprint.core.crypto.Hmac;
import com.secureprint.core.domain.ColorMode;
import com.secureprint.core.domain.DuplexMode;
import com.secureprint.core.domain.Employee;
import com.secureprint.core.domain.JobState;
import com.secureprint.core.domain.PaperSize;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.core.domain.Printer;
import com.secureprint.core.domain.PrinterStatus;
import com.secureprint.core.domain.Capability;
import com.secureprint.core.store.FileSpoolStore;
import com.secureprint.core.store.SpoolEnvelope;
import com.secureprint.core.store.SpoolStore;
import com.secureprint.server.config.ServerConfig;
import com.secureprint.server.security.ReleaseTokenService;
import com.secureprint.server.service.AgentRegistry;
import com.secureprint.server.service.ExpirySweeper;
import com.secureprint.server.service.ReleaseService;
import com.secureprint.server.service.SubmissionService;
import com.secureprint.server.store.InMemoryJobStore;
import com.secureprint.core.crypto.Ecies;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Fixture wiring a complete server instance for behavioural tests. */
abstract class ServerTestBase {

    static final Instant NOW = Instant.parse("2026-11-25T10:00:00Z");
    static final String SITE_SH = "site-shanghai";
    static final String SITE_MUC = "site-munich";

    InMemoryJobStore store;
    FileSpoolStore spool;
    SpoolEnvelope envelope;
    ServerConfig config;
    ReleaseTokenService tokens;
    SubmissionService submissions;
    ReleaseService releases;
    AgentRegistry agents;
    Clock clock;
    Path spoolDir;
    ExpirySweeper sweeper;
    final List<String> auditEvents = new java.util.ArrayList<>();

    @BeforeEach
    void setUp() throws IOException {
        clock = Clock.fixed(NOW, ZoneOffset.UTC);
        store = new InMemoryJobStore();
        spoolDir = Files.createTempDirectory("spool-test");
        spool = new FileSpoolStore(spoolDir);
        config = ServerConfig.ephemeralDefaults();
        envelope = new SpoolEnvelope(config.masterSecret());
        tokens = new ReleaseTokenService(config.masterSecret());
        submissions = new SubmissionService(store, spool, envelope, tokens, config, clock);
        agents = new AgentRegistry();
        releases = new ReleaseService(store, spool, envelope, agents, config, clock, tokens);
        sweeper = new ExpirySweeper(store, spool, clock, 100,
                (action, jobId, actor, detail) ->
                        auditEvents.add(action + "|" + jobId + "|" + actor + "|" + detail));
    }

    @AfterEach
    void tearDown() throws IOException {
        try (var walk = Files.walk(spoolDir)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best effort cleanup
                }
            });
        }
    }

    Employee employee(String id, String badgeUid, String site) {
        Employee e = new Employee(id, "Name " + id, "Finance", id + "@example.com",
                Hmac.badgeDigest(config.badgePepper(), badgeUid), site, true, NOW);
        store.saveEmployee(e);
        return e;
    }

    Printer printer(String id, String site, boolean color) {
        var caps = EnumSet.of(Capability.MONO, Capability.A4, Capability.DUPLEX);
        if (color) {
            caps.add(Capability.COLOR);
        }
        Printer p = new Printer(id, "HP LaserJet Test", "hp.laserjet.pcl5.raw9100", site, "lp",
                "127.0.0.1", 9100, caps, PrinterStatus.IDLE);
        store.savePrinter(p);
        return p;
    }

    AgentRegistry.Agent agent(String agentId, String site) {
        Ecies.RecipientKeys keys = Ecies.recipientKeys();
        return agents.enroll(agentId, site, keys.publicEncoded(), NOW);
    }

    String submit(String employeeId, String text) {
        return submit(employeeId, text, config.defaultHoldTtl());
    }

    String submit(String employeeId, String text, Duration ttl) {
        var sub = submissions.submit(new SubmissionService.SubmitRequest(
                employeeId, "payslip.txt", "text/plain",
                text.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                1, ColorMode.MONO, DuplexMode.SIMPLEX, PaperSize.A4, List.of(),
                "PAYROLL", ttl));
        return sub.jobId() + "::" + sub.releaseToken();
    }

    String jobId(String submitted) {
        return submitted.substring(0, submitted.indexOf("::"));
    }

    String token(String submitted) {
        return submitted.substring(submitted.indexOf("::") + 2);
    }

    /** Simulates the server clock moving forward, re-creating services against a new clock. */
    void moveClockTo(Instant instant) {
        clock = Clock.fixed(instant, ZoneOffset.UTC);
        submissions = new SubmissionService(store, spool, envelope, tokens, config, clock);
        releases = new ReleaseService(store, spool, envelope, agents, config, clock, tokens);
        sweeper = new ExpirySweeper(store, spool, clock, 100,
                (action, jobId, actor, detail) ->
                        auditEvents.add(action + "|" + jobId + "|" + actor + "|" + detail));
    }
}
