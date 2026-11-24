package com.secureprint.server.service;

import com.secureprint.core.crypto.Ecies;
import com.secureprint.core.crypto.Hmac;
import com.secureprint.core.domain.Employee;
import com.secureprint.core.domain.JobState;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.core.domain.Printer;
import com.secureprint.core.protocol.GrantSigning;
import com.secureprint.core.protocol.ManifestVerifier;
import com.secureprint.core.protocol.ReleaseGrant;
import com.secureprint.core.store.SpoolEnvelope;
import com.secureprint.core.store.SpoolStore;
import com.secureprint.core.util.Bytes;
import com.secureprint.server.config.ServerConfig;
import com.secureprint.server.security.ReleaseTokenService;
import com.secureprint.server.store.JobStore;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * The online release flow: an employee authenticates at a release terminal, the server decides,
 * and a signed, job-scoped grant is returned to the agent.
 *
 * <p>Security properties this class is responsible for:
 * <ol>
 *   <li><b>Ownership.</b> A job is only released to its owner. The employee id comes from the
 *       badge hash looked up server-side, never from a client-supplied field.</li>
 *   <li><b>Single use.</b> {@link JobStore#claimForRelease} atomically flips HELD → RELEASING, so
 *       two terminals racing for the same job yield exactly one grant.</li>
 *   <li><b>Binding.</b> The grant is bound to job, employee, agent and printer, and signed, so an
 *       agent cannot repurpose it or a compromised terminal cannot widen it.</li>
 *   <li><b>Key separation.</b> The agent receives the job's data key only wrapped to that agent's
 *       X25519 key and bound by AAD to (agent, job, owner). A grant is useless to any other agent,
 *       and to anyone who captures it off the wire.</li>
 * </ol>
 */
public final class ReleaseService {

    private final JobStore store;
    private final SpoolStore spool;
    private final SpoolEnvelope envelope;
    private final AgentRegistry agents;
    private final ServerConfig config;
    private final Clock clock;
    private final ReleaseTokenService tokens;

    public ReleaseService(JobStore store, SpoolStore spool, SpoolEnvelope envelope,
                          AgentRegistry agents, ServerConfig config, Clock clock,
                          ReleaseTokenService tokens) {
        this.store = store;
        this.spool = spool;
        this.envelope = envelope;
        this.agents = agents;
        this.config = config;
        this.clock = clock;
        this.tokens = tokens;
    }

    /** Everything the employee can release at this site right now. */
    public List<PrintJob> pendingFor(String employeeId) {
        return pendingFor(employeeId, null);
    }

    /** Pending jobs collectable at {@code siteId}; null means any site. */
    public List<PrintJob> pendingFor(String employeeId, String siteId) {
        return store.jobsFor(employeeId).stream()
                .filter(j -> j.state() == JobState.HELD && !j.isExpiredAt(clock.instant()))
                .filter(j -> siteId == null || j.collectableAt(siteId))
                .toList();
    }

    public record AuthOutcome(String employeeId, String displayName, List<PrintJob> pending) {
    }

    /**
     * Identifies the employee from a badge tap.
     *
     * @param rawBadgeUid the raw UID read by the terminal; hashed with the pepper before any
     *                    lookup. It is never logged or stored.
     */
    public Optional<AuthOutcome> authenticateBadge(String rawBadgeUid) {
        return authenticateBadge(rawBadgeUid, null);
    }

    public Optional<AuthOutcome> authenticateBadge(String rawBadgeUid, String siteId) {
        String digest = Hmac.badgeDigest(config.badgePepper(), rawBadgeUid);
        return store.employeeByBadgeHash(digest)
                .filter(Employee::active)
                .map(e -> new AuthOutcome(e.employeeId(), e.displayName(),
                        pendingFor(e.employeeId(), siteId)));
    }

    /** Identifies the employee from a signed QR payload (same one-time token issued at submit). */

    public record Grant(String grantJson, String signatureB64, ReleaseGrant grant) {
    }

    /**
     * Releases one job to one printer.
     *
     * @throws ReleaseDenied with a safe reason on any policy failure
     */
    public Grant release(String jobId, String employeeId, String releaseToken,
                         String agentId, String printerId) {
        AgentRegistry.Agent agent = agents.agent(agentId)
                .filter(AgentRegistry.Agent::enabled)
                .orElseThrow(() -> new ReleaseDenied("agent not enrolled or disabled"));

        Printer printer = store.printer(printerId)
                .orElseThrow(() -> new ReleaseDenied("unknown printer"));
        if (!printer.siteId().equals(agent.siteId())) {
            // An agent may only drive devices at its own site: this stops a compromised branch box
            // from printing someone's payslip on a printer in another country.
            throw new ReleaseDenied("printer is not at the agent's site");
        }

        PrintJob job = store.job(jobId)
                .orElseThrow(() -> new ReleaseDenied("unknown job"));
        if (!job.ownerEmployeeId().equals(employeeId)) {
            throw new ReleaseDenied("job does not belong to this employee");
        }
        if (!job.collectableAt(agent.siteId())) {
            // The employee is at a site their job was not routed to. Without this an employee
            // travelling to a branch would be able to pull a document they deliberately kept
            // for their home print room; routing is an explicit allow-list.
            throw new ReleaseDenied("job cannot be collected at this site");
        }
        if (!tokens.verify(releaseToken, job.releaseTokenHash())) {
            throw new ReleaseDenied("invalid release token");
        }

        Instant now = clock.instant();
        if (job.isExpiredAt(now)) {
            throw new ReleaseDenied("job hold window has expired");
        }
        if (job.color() && !printer.supports(com.secureprint.core.domain.Capability.COLOR)) {
            throw new ReleaseDenied("printer does not support colour");
        }
        if (!printer.isReachable()) {
            throw new ReleaseDenied("printer is not online");
        }
        if (!store.claimForRelease(jobId, employeeId, now)) {
            throw new ReleaseDenied("job is no longer available (already released or expired)");
        }

        try {
            byte[] packedSpool = spool.get(job.spoolObjectId())
                    .orElseThrow(() -> new ReleaseDenied("spool object missing"));
            SpoolEnvelope.Sealed sealed = SpoolEnvelope.unpack(packedSpool);

            byte[] dataKey = envelope.unwrapDataKey(job.jobId(), job.ownerEmployeeId(),
                    sealed.wrappedKey());
            byte[] wrappedForAgent;
            try {
                wrappedForAgent = Ecies.seal(agent.publicKey(), dataKey,
                        SpoolEnvelope.agentKeyAad(agentId, job.jobId(), employeeId));
            } finally {
                java.util.Arrays.fill(dataKey, (byte) 0);
            }

            Instant issuedAt = now;
            ReleaseGrant grant = new ReleaseGrant(
                    "grant-" + Bytes.b64url(Bytes.random(16)),
                    job.jobId(),
                    employeeId,
                    agentId,
                    printerId,
                    Bytes.b64url(Bytes.random(16)),
                    ReleaseGrant.Mode.ONLINE,
                    issuedAt,
                    issuedAt.minusSeconds(2),
                    issuedAt.plus(config.grantTtl()),
                    Bytes.b64url(wrappedForAgent),
                    agent.fingerprint());

            byte[] signature = ManifestVerifier.sign(config.serverSigningKey().getPrivate(), grant);
            agents.recordSeen(agentId, agent.lastSequence(), now);
            return new Grant(com.secureprint.core.util.Json.toJson(grant),
                    Bytes.b64url(signature), grant);
        } catch (RuntimeException e) {
            // Roll the job back so the employee can retry at another printer instead of losing it.
            store.job(jobId).ifPresent(j ->
                    store.saveJob(j.withState(JobState.HELD)));
            if (e instanceof ReleaseDenied denied) {
                throw denied;
            }
            throw new ReleaseDenied("release failed: " + e.getClass().getSimpleName());
        }
    }

    /**
     * Mints an OFFLINE-mode grant for a job, while the server is reachable.
     *
     * <p>This is how a partitioned branch still releases documents: the server pre-authorises a
     * bounded set of releases during each sync. Differences from an ONLINE grant:
     * <ul>
     *   <li>It does <b>not</b> claim the job. The job stays HELD, so an online release elsewhere
     *       can still win; the offline path is optimistic by construction.</li>
     *   <li>It carries a short TTL (the manifest's), so a captured grant is useless after that.</li>
     *   <li>The agent additionally requires the job to still be in its current manifest at print
     *       time, which drops it if a later sync showed the job cancelled or released.</li>
     * </ul>
     *
     * <p>Because the job is not claimed, an offline grant and an online release can both succeed
     * across a partition. That is a real, documented limitation of partition-tolerant printing;
     * reconciliation detects it and flags it rather than pretending it cannot happen.
     */
    public Grant issueOfflineGrant(String jobId, String employeeId, String agentId,
                                   String printerId) {
        AgentRegistry.Agent agent = agents.agent(agentId)
                .filter(AgentRegistry.Agent::enabled)
                .orElseThrow(() -> new ReleaseDenied("agent not enrolled or disabled"));
        Printer printer = store.printer(printerId)
                .orElseThrow(() -> new ReleaseDenied("unknown printer"));
        if (!printer.siteId().equals(agent.siteId())) {
            throw new ReleaseDenied("printer is not at the agent's site");
        }
        PrintJob job = store.job(jobId).orElseThrow(() -> new ReleaseDenied("unknown job"));
        if (!job.ownerEmployeeId().equals(employeeId)) {
            throw new ReleaseDenied("job does not belong to this employee");
        }
        if (!job.collectableAt(agent.siteId())) {
            throw new ReleaseDenied("job cannot be collected at this site");
        }
        Instant now = clock.instant();
        if (job.state() != JobState.HELD || job.isExpiredAt(now)) {
            throw new ReleaseDenied("job is not available for offline release");
        }

        byte[] packedSpool = spool.get(job.spoolObjectId())
                .orElseThrow(() -> new ReleaseDenied("spool object missing"));
        SpoolEnvelope.Sealed sealed = SpoolEnvelope.unpack(packedSpool);
        byte[] dataKey = envelope.unwrapDataKey(job.jobId(), job.ownerEmployeeId(),
                sealed.wrappedKey());
        byte[] wrappedForAgent;
        try {
            wrappedForAgent = Ecies.seal(agent.publicKey(), dataKey,
                    SpoolEnvelope.agentKeyAad(agentId, job.jobId(), employeeId));
        } finally {
            java.util.Arrays.fill(dataKey, (byte) 0);
        }
        // Offline grants live no longer than the job's own hold window or the manifest TTL.
        Instant expiresAt = now.plus(config.manifestTtl());
        if (expiresAt.isAfter(job.holdUntil())) {
            expiresAt = job.holdUntil();
        }
        ReleaseGrant grant = new ReleaseGrant("grant-" + Bytes.b64url(Bytes.random(16)),
                job.jobId(), employeeId, agentId, printerId, Bytes.b64url(Bytes.random(16)),
                ReleaseGrant.Mode.OFFLINE, now, now.minusSeconds(2), expiresAt,
                Bytes.b64url(wrappedForAgent), agent.fingerprint());
        byte[] signature = ManifestVerifier.sign(config.serverSigningKey().getPrivate(), grant);
        return new Grant(com.secureprint.core.util.Json.toJson(grant), Bytes.b64url(signature),
                grant);
    }

    /** Marks the outcome reported by the agent after it talks to the device. */
    public void confirmReleased(String agentId, String jobId) {
        PrintJob job = store.job(jobId).orElse(null);
        if (job == null) {
            return;
        }
        if (job.state() == JobState.RELEASING || job.state() == JobState.HELD) {
            store.saveJob(purge(job.released(agentId, clock.instant())));
        }
    }

    /**
     * Destroys the spool blob for a job that will never be printed again. Keeps the metadata for
     * audit but clears the spool reference, so the ciphertext — and the wrapped data key inside
     * it — no longer exists anywhere. Without this a released payslip would sit decryptable on the
     * server until the end of time, since the expiry sweeper only looks at uncollected jobs.
     */
    private PrintJob purge(PrintJob job) {
        if (job.spoolObjectId() != null && !job.spoolObjectId().isEmpty()) {
            spool.delete(job.spoolObjectId());
        }
        return job.withoutSpool();
    }

    /** Deletes the blob of a job BEFORE tombstoning it (the tombstone clears the reference). */
    private PrintJob purgeThen(PrintJob source, java.util.function.UnaryOperator<PrintJob> f) {
        if (source.spoolObjectId() != null && !source.spoolObjectId().isEmpty()) {
            spool.delete(source.spoolObjectId());
        }
        return f.apply(source);
    }

    /**
     * Reconciles an offline release reported by an agent after a partition.
     *
     * <p>Four cases, all of which must be represented honestly in the audit trail:
     * <ol>
     *   <li><b>DELIVERED and server still HELD</b> — the expected case. Job becomes RELEASED.</li>
     *   <li><b>DELIVERED but server already RELEASED elsewhere</b> — a genuine double print across
     *       a partition. We keep RELEASED and flag it; the record must not pretend it printed
     *       once.</li>
     *   <li><b>DELIVERED but server CANCELLED or EXPIRED during the partition</b> — the employee
     *       has paper the server thought was destroyed. Mark FAILED with an explicit reason so a
     *       DLP review can follow up; we never silently rewrite history.</li>
     *   <li><b>FAILED</b> — release it back to HELD so the employee can retry.</li>
     * </ol>
     */
    public ReconcileResult reconcileOffline(String agentId, String jobId, boolean delivered,
                                            String detail) {
        PrintJob job = store.job(jobId).orElse(null);
        if (job == null) {
            return ReconcileResult.UNKNOWN_JOB;
        }
        if (!delivered) {
            if (job.state() == JobState.HELD || job.state() == JobState.OFFLINE_UNCONFIRMED) {
                store.saveJob(job.withState(JobState.HELD));
            }
            return ReconcileResult.REVERTED_TO_HELD;
        }
        return switch (job.state()) {
            case HELD, RELEASING, OFFLINE_UNCONFIRMED -> {
                store.saveJob(purge(job.released(agentId, clock.instant())));
                yield ReconcileResult.CONFIRMED;
            }
            case RELEASED -> ReconcileResult.ALREADY_RELEASED_DOUBLE_PRINT;
            case CANCELLED -> {
                store.saveJob(purgeThen(job, j -> j.tombstone(JobState.FAILED,
                        "printed offline after cancellation; reconciliation flag")));
                yield ReconcileResult.PRINTED_AFTER_CANCEL;
            }
            case EXPIRED -> {
                store.saveJob(purgeThen(job, j -> j.tombstone(JobState.FAILED,
                        "printed offline after expiry; reconciliation flag")));
                yield ReconcileResult.PRINTED_AFTER_EXPIRY;
            }
            case FAILED -> ReconcileResult.ALREADY_FAILED;
        };
    }

    /** Outcome of reconciling one offline release. Every value maps to an audit action. */
    public enum ReconcileResult {
        CONFIRMED,
        REVERTED_TO_HELD,
        ALREADY_RELEASED_DOUBLE_PRINT,
        PRINTED_AFTER_CANCEL,
        PRINTED_AFTER_EXPIRY,
        ALREADY_FAILED,
        UNKNOWN_JOB
    }

    public void confirmFailed(String agentId, String jobId, String reason, boolean retryable) {
        PrintJob job = store.job(jobId).orElse(null);
        if (job == null) {
            return;
        }
        if (!retryable) {
            store.saveJob(purge(job.failed(reason)));
            return;
        }
        // Retryable: put it back so the employee can tap again at another device.
        if (job.state() == JobState.RELEASING) {
            store.saveJob(job.withState(JobState.HELD));
        }
    }

    /** Employee-initiated cancel before release. */
    public boolean cancel(String jobId, String employeeId) {
        PrintJob job = store.job(jobId).orElse(null);
        if (job == null || !job.ownerEmployeeId().equals(employeeId)) {
            return false;
        }
        if (job.state() != JobState.HELD && job.state() != JobState.RELEASING) {
            return false;
        }
        // A cancelled document must not linger: destroy its bytes now rather than waiting for the
        // next sweep (which in any case skips cancelled jobs).
        store.saveJob(purgeThen(job, j -> j.tombstone(JobState.CANCELLED,
                "cancelled by owner")));
        return true;
    }

    /** Expected, policy-driven refusal. The message is safe to show a user. */
    public static final class ReleaseDenied extends RuntimeException {
        public ReleaseDenied(String message) {
            super(message);
        }
    }

    /** Exposed so tests and the app can verify grants exactly as an agent would. */
    public boolean verifyGrant(Grant grant, byte[] signature) {
        return com.secureprint.core.crypto.Ed25519.verify(
                config.serverSigningKey().getPublic(),
                GrantSigning.canonicalGrant(grant.grant()), signature);
    }
}
