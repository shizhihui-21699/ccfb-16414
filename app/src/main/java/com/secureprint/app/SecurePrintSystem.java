package com.secureprint.app;

import com.secureprint.core.crypto.Ed25519;
import com.secureprint.core.crypto.Ecies;
import com.secureprint.core.crypto.Hmac;
import com.secureprint.core.domain.Employee;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.core.domain.Printer;
import com.secureprint.core.store.FileSpoolStore;
import com.secureprint.core.store.SpoolEnvelope;
import com.secureprint.core.store.SpoolStore;
import com.secureprint.server.config.ServerConfig;
import com.secureprint.server.security.ReleaseTokenService;
import com.secureprint.server.service.AgentRegistry;
import com.secureprint.server.service.AuditingService;
import com.secureprint.server.service.ExpirySweeper;
import com.secureprint.server.service.ManifestService;
import com.secureprint.server.service.ReleaseService;
import com.secureprint.server.service.SubmissionService;
import com.secureprint.server.store.InMemoryJobStore;
import com.secureprint.server.store.JobStore;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Composition root: wires every server component together so the HTTP layer, the demo and the
 * tests all exercise the same object graph.
 *
 * <p>Explicit construction (rather than a DI container) is a deliberate choice for a security
 * component: the dependency graph <em>is</em> the trust boundary, and it should be readable in
 * one screen. If you cannot see how spool keys flow from here, that is a design smell.
 */
public final class SecurePrintSystem {

    public final ServerConfig config;
    public final Clock clock;
    public final JobStore store;
    public final SpoolStore spool;
    public final SpoolEnvelope envelope;
    public final ReleaseTokenService tokens;
    public final SubmissionService submissions;
    public final ReleaseService releases;
    public final ManifestService manifests;
    public final AgentRegistry agents;
    public final AuditingService audit;
    public final ExpirySweeper sweeper;

    public SecurePrintSystem(Path spoolDir, ServerConfig config, Clock clock) {
        this.config = config;
        this.clock = clock;
        this.store = new InMemoryJobStore();
        this.spool = new FileSpoolStore(spoolDir);
        this.envelope = new SpoolEnvelope(config.masterSecret());
        this.tokens = new ReleaseTokenService(config.masterSecret());
        this.submissions = new SubmissionService(store, spool, envelope, tokens, config, clock);
        this.agents = new AgentRegistry();
        this.releases = new ReleaseService(store, spool, envelope, agents, config, clock, tokens);
        this.manifests = new ManifestService(store, spool, envelope, agents, config, clock);
        this.audit = new AuditingService(clock, event -> { /* durable sink supplied by deployment */ });
        this.sweeper = new ExpirySweeper(store, spool, clock, config.expirySweepBatch(),
                (action, jobId, actor, detail) ->
                        audit.record(AuditingService.Action.JOB_EXPIRED_DESTROYED, actor,
                                "SYSTEM", jobId, null, null, detail));
    }

    // ---------- convenience operations used by the demo and the HTTP layer ----------

    public Employee addEmployee(String id, String name, String dept, String email,
                                String rawBadgeUid, String site, java.util.Set<String> travel) {
        Employee e = new Employee(id, name, dept, email,
                Hmac.badgeDigest(config.badgePepper(), rawBadgeUid), site, travel, true,
                clock.instant());
        store.saveEmployee(e);
        return e;
    }

    public Printer addPrinter(String printerId, String model, String driverId, String site,
                              String host, int port, java.util.Set<com.secureprint.core.domain.Capability> caps) {
        Printer p = new Printer(printerId, model, driverId, site, "lp", host, port, caps,
                com.secureprint.core.domain.PrinterStatus.IDLE);
        store.savePrinter(p);
        return p;
    }

    public AgentRegistry.Agent enrollAgent(String agentId, String site) {
        Ecies.RecipientKeys keys = Ecies.recipientKeys();
        AgentRegistry.Agent agent = agents.enroll(agentId, site, keys.publicEncoded(),
                clock.instant());
        audit.record(AuditingService.Action.AGENT_ENROLLED, "admin", "ADMIN", null, null, site,
                "agent=" + agentId + " fp=" + agent.fingerprint());
        return agent;
    }

    /**
     * Enrols an agent whose key pair was generated on the agent itself and whose public half was
     * carried over on a USB stick or by an admin — the production provisioning flow.
     */
    public AgentRegistry.Agent enrollAgent(String agentId, String site,
                                           Ecies.RecipientKeys publicKeys) {
        AgentRegistry.Agent agent = agents.enroll(agentId, site, publicKeys.publicEncoded(),
                clock.instant());
        audit.record(AuditingService.Action.AGENT_ENROLLED, "admin", "ADMIN", null, null, site,
                "agent=" + agentId + " fp=" + agent.fingerprint());
        return agent;
    }

    public SubmissionService.Submitted submit(String employeeId, String documentName,
                                              String mimeType, byte[] document) {
        SubmissionService.Submitted submitted = submissions.submit(
                new SubmissionService.SubmitRequest(employeeId, documentName, mimeType, document,
                        1, com.secureprint.core.domain.ColorMode.MONO,
                        com.secureprint.core.domain.DuplexMode.SIMPLEX,
                        com.secureprint.core.domain.PaperSize.A4, List.of(),
                        "PAYROLL", config.defaultHoldTtl()));
        audit.record(AuditingService.Action.JOB_SUBMITTED, employeeId, "EMPLOYEE",
                submitted.jobId(), null, null,
                "doc-class=PAYROLL name=" + documentName);
        return submitted;
    }

    public ReleaseService.Grant release(String jobId, String employeeId, String token,
                                        String agentId, String printerId) {
        try {
            ReleaseService.Grant grant = releases.release(jobId, employeeId, token, agentId,
                    printerId);
            audit.record(AuditingService.Action.RELEASE_GRANTED, employeeId, "EMPLOYEE", jobId,
                    printerId, printerSite(printerId), "mode=ONLINE");
            return grant;
        } catch (ReleaseService.ReleaseDenied denied) {
            audit.record(AuditingService.Action.RELEASE_DENIED, employeeId, "EMPLOYEE", jobId,
                    printerId, printerSite(printerId), denied.getMessage());
            throw denied;
        }
    }

    private String printerSite(String printerId) {
        return store.printer(printerId).map(Printer::siteId).orElse(null);
    }

    public void confirmReleased(String agentId, String jobId) {
        releases.confirmReleased(agentId, jobId);
        audit.record(AuditingService.Action.RELEASE_CONFIRMED, null, "AGENT", jobId, null,
                null, "agent=" + agentId);
    }

    public void confirmFailed(String agentId, String jobId, String reason, boolean retryable) {
        releases.confirmFailed(agentId, jobId, reason, retryable);
        audit.record(AuditingService.Action.RELEASE_FAILED, null, "AGENT", jobId, null, null,
                "agent=" + agentId + " retryable=" + retryable + " reason=" + reason);
    }

    public boolean cancel(String jobId, String employeeId) {
        boolean ok = releases.cancel(jobId, employeeId);
        if (ok) {
            audit.record(AuditingService.Action.JOB_CANCELLED, employeeId, "EMPLOYEE", jobId,
                    null, null, null);
        }
        return ok;
    }

    public List<PrintJob> pending(String employeeId, String siteId) {
        return releases.pendingFor(employeeId, siteId);
    }

    public Map<String, Object> health() {
        return Map.of(
                "status", "ok",
                "jobs", store.allJobs().size(),
                "printers", store.printers().size(),
                "agents", agents.all().size(),
                "auditHead", audit.lastHash(),
                "driverKeyFingerprint", Ed25519.encodePublic(
                        config.serverSigningKey().getPublic()).substring(0, 12));
    }

    /**
     * Adapter that lets an in-process agent reconcile against this server. Production uses an
     * HTTP implementation of the same one-method interface.
     */
    public com.secureprint.agent.sync.OfflineReconciler.ServerGateway reconcilerGateway() {
        return (agentId, jobId, delivered, detail) -> {
            ReleaseService.ReconcileResult result =
                    releases.reconcileOffline(agentId, jobId, delivered, detail);
            audit.record(AuditingService.Action.OFFLINE_RELEASE_UNCONFIRMED, null, "AGENT",
                    jobId, null, null, "reconcile=" + result.name() + " " + detail);
            return new com.secureprint.agent.sync.OfflineReconciler.Result(result.name(), detail);
        };
    }

    /** Convenience for tests that want a short digest of a badge. */
    public String badgeDigest(String raw) {
        return Hmac.badgeDigest(config.badgePepper(), raw);
    }
}
