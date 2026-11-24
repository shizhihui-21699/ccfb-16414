package com.secureprint.core.protocol;

import java.time.Instant;
import java.util.List;

/**
 * Server-signed, site-scoped, time-bounded list of jobs a release agent may print while it
 * cannot reach the server.
 *
 * <p>This is the offline path's entire trust anchor. The agent verifies one signature over the
 * whole manifest and then enforces, locally, the same ownership rule the server would: a held
 * job can only be released by its owner, before {@code holdUntil}.
 *
 * <p>Deliberately coarse: one signature per sync, not per job — a sync of 500 jobs costs one
 * Ed25519 verification, which matters on the small ARM boxes used in branch print rooms.
 */
public record ReleaseManifest(
        String manifestId,
        String agentId,
        String siteId,
        long sequence,
        Instant issuedAt,
        Instant notBefore,
        Instant expiresAt,
        List<Entry> entries) {

    public ReleaseManifest {
        if (manifestId == null || agentId == null || siteId == null) {
            throw new IllegalArgumentException("manifest identity fields are mandatory");
        }
        entries = entries == null ? List.of() : List.copyOf(entries);
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("manifest must expire after issue");
        }
    }

    /**
     * One releasable job.
     *
     * @param jobDataKeyWrapped ECIES(agentPublicKey, job data key), so this agent — and only this
     *                          agent — can decrypt the spool blob it also downloaded.
     */
    public record Entry(
            String jobId,
            String employeeId,
            String documentName,
            Instant holdUntil,
            String spoolObjectId,
            String jobDataKeyWrapped,
            boolean colorOnly) {

        public Entry {
            if (jobId == null || employeeId == null || spoolObjectId == null) {
                throw new IllegalArgumentException("manifest entry identity fields are mandatory");
            }
        }
    }

    public boolean isUsableAt(Instant now) {
        return !now.isBefore(notBefore) && now.isBefore(expiresAt);
    }

    public List<Entry> entriesFor(String employeeId) {
        return entries.stream().filter(e -> e.employeeId().equals(employeeId)).toList();
    }

    public Entry entry(String jobId) {
        return entries.stream().filter(e -> e.jobId().equals(jobId)).findFirst().orElse(null);
    }
}
