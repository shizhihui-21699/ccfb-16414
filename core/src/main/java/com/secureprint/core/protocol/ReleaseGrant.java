package com.secureprint.core.protocol;

import java.time.Instant;

/**
 * Server-signed authorization to release exactly one job, to one printer, once.
 *
 * <p>A grant is minted only after the server has authenticated the employee. The agent's job
 * is to enforce the grant, not to decide entitlement.
 *
 * <p>{@code mode} distinguishes:
 * <ul>
 *   <li>{@link Mode#ONLINE} — minted in response to a live badge tap; the server has already
 *       atomically moved the job to RELEASING, so concurrent taps elsewhere fail.</li>
 *   <li>{@link Mode#OFFLINE} — pre-minted during the last successful sync, bounded by
 *       {@code expiresAt} and by the agent's maximum tolerated staleness. Strongly weaker:
 *       the server cannot see it happen, so two branch offices can both print the same job if
 *       the WAN is partitioned on both sides. See docs/DESIGN.md §"Offline release".</li>
 * </ul>
 */
public record ReleaseGrant(
        String grantId,
        String jobId,
        String employeeId,
        String agentId,
        String printerId,
        String nonce,
        Mode mode,
        Instant issuedAt,
        Instant notBefore,
        Instant expiresAt,
        String jobDataKeyWrapped,   // ECIES(agentPub, jobDataKey), see WrapTarget
        String wrapTargetFingerprint) {

    public enum Mode {
        ONLINE,
        OFFLINE
    }

    public ReleaseGrant {
        if (grantId == null || jobId == null || employeeId == null || agentId == null
                || printerId == null || nonce == null) {
            throw new IllegalArgumentException("grant identity fields are mandatory");
        }
        if (expiresAt == null || issuedAt == null) {
            throw new IllegalArgumentException("grant time bounds are mandatory");
        }
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("grant must expire after issue");
        }
    }

    public boolean isUsableAt(Instant now) {
        return !now.isBefore(notBefore) && now.isBefore(expiresAt);
    }
}
