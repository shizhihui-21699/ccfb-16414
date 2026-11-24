package com.secureprint.server.service;

import com.secureprint.core.crypto.Ecies;
import com.secureprint.core.domain.JobState;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.core.protocol.ManifestVerifier;
import com.secureprint.core.protocol.ReleaseManifest;
import com.secureprint.core.store.SpoolEnvelope;
import com.secureprint.core.store.SpoolStore;
import com.secureprint.core.util.Bytes;
import com.secureprint.server.config.ServerConfig;
import com.secureprint.server.store.JobStore;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Builds the signed, site-scoped manifests that let a branch agent release jobs while the WAN is
 * down.
 *
 * <p>The offline design in one paragraph: during each successful sync, the server sends the agent
 * (a) the sealed spool blobs for jobs belonging to employees who are currently at that site, and
 * (b) a manifest listing those jobs with each job's data key wrapped to this agent. The agent
 * keeps both on local disk. When the WAN drops, a badge tap is authorized against the manifest:
 * the job must be in it, belong to the tapped employee, and not be past its hold deadline. The
 * agent then decrypts and prints. When the WAN returns, the agent uploads an audit reconciliation
 * and learns which of its offline releases the server has since invalidated.
 *
 * <p><b>Honest limitation:</b> partitioning can let the same job print twice — once offline at
 * one site and again online elsewhere — or print after a server-side cancel. The mitigations are
 * (1) manifests carry a short TTL (hours, not days) and a strict sequence, (2) the agent refuses
 * to release anything whose grant window has closed, (3) an offline release is recorded as
 * "OFFLINE_UNCONFIRMED" until reconciled, so the audit trail never claims certainty it lacks.
 * A fully partition-tolerant exactly-once release would need a consensus protocol across sites;
 * that trade-off is documented in docs/DESIGN.md rather than hidden.
 */
public final class ManifestService {

    private final JobStore store;
    private final SpoolStore spool;
    private final SpoolEnvelope envelope;
    private final AgentRegistry agents;
    private final ServerConfig config;
    private final Clock clock;

    public ManifestService(JobStore store, SpoolStore spool, SpoolEnvelope envelope,
                           AgentRegistry agents, ServerConfig config, Clock clock) {
        this.store = store;
        this.spool = spool;
        this.envelope = envelope;
        this.agents = agents;
        this.config = config;
        this.clock = clock;
    }

    public record Bundle(ReleaseManifest manifest, String signatureB64,
                         List<SpoolBlob> blobs) {
    }

    /**
     * A sealed spool blob to push to the agent. Delivered separately from the manifest so the
     * manifest stays small enough for a constrained link, and so blobs can be resumed.
     */
    public record SpoolBlob(String objectId, byte[] packed) {
    }

    public Optional<Bundle> buildForAgent(String agentId) {
        AgentRegistry.Agent agent = agents.agent(agentId)
                .filter(AgentRegistry.Agent::enabled)
                .orElse(null);
        if (agent == null) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        Instant expires = now.plus(config.manifestTtl());
        long sequence = agent.lastSequence() + 1;

        record Candidate(PrintJob job, byte[] wrappedKey) {
        }

        List<Candidate> candidates = new ArrayList<>();
        for (PrintJob job : store.jobsForSite(agent.siteId())) {
            if (job.state() != JobState.HELD || job.isExpiredAt(now)) {
                continue;
            }
            Optional<byte[]> packed = spool.get(job.spoolObjectId());
            if (packed.isEmpty()) {
                continue;
            }
            SpoolEnvelope.Sealed sealed = SpoolEnvelope.unpack(packed.get());
            byte[] dataKey = envelope.unwrapDataKey(job.jobId(), job.ownerEmployeeId(),
                    sealed.wrappedKey());
            try {
                byte[] wrapped = Ecies.seal(agent.publicKey(), dataKey,
                        SpoolEnvelope.agentKeyAad(agent.agentId(), job.jobId(),
                                job.ownerEmployeeId()));
                candidates.add(new Candidate(job, wrapped));
            } finally {
                java.util.Arrays.fill(dataKey, (byte) 0);
            }
        }

        candidates.sort(Comparator.comparing(c -> c.job().jobId()));

        List<ReleaseManifest.Entry> entries = candidates.stream()
                .map(c -> new ReleaseManifest.Entry(
                        c.job().jobId(),
                        c.job().ownerEmployeeId(),
                        c.job().documentName(),
                        c.job().holdUntil(),
                        c.job().spoolObjectId(),
                        Bytes.b64url(c.wrappedKey()),
                        c.job().color()))
                .toList();

        ReleaseManifest manifest = new ReleaseManifest(
                "man-" + Bytes.b64url(Bytes.random(12)),
                agent.agentId(),
                agent.siteId(),
                sequence,
                now,
                now.minusSeconds(5),
                expires,
                entries);
        byte[] signature = ManifestVerifier.sign(config.serverSigningKey().getPrivate(), manifest);

        List<SpoolBlob> blobs = new ArrayList<>();
        for (Candidate c : candidates) {
            spool.get(c.job().spoolObjectId())
                    .ifPresent(b -> blobs.add(new SpoolBlob(c.job().spoolObjectId(), b)));
        }
        return Optional.of(new Bundle(manifest, Bytes.b64url(signature), blobs));
    }

    /** Records that an agent pulled the manifest with this sequence. */
    public void acknowledge(String agentId, long sequence) {
        agents.recordSeen(agentId, sequence, clock.instant());
    }
}
