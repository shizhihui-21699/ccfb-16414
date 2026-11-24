package com.secureprint.core.domain;

import java.time.Instant;
import java.util.Set;

/**
 * Immutable record describing a held job. Document bytes live only inside the encrypted spool
 * under {@code spoolObjectId}; nothing in this record is sensitive apart from
 * {@code ownerEmployeeId} and {@code documentName}, which are needed for the release terminal's
 * job picker.
 *
 * <p>{@code collectSites} is the routing set copied from the employee at submission time: the
 * home site plus any travel sites. It is snapshotted rather than looked up live so a submission
 * is never silently re-routed by a later HR change, and so the manifest builder is a simple
 * index query.
 */
public record PrintJob(
        String jobId,
        String ownerEmployeeId,
        String homeSiteId,
        Set<String> collectSites,
        String documentName,
        String documentClass,
        long sizeBytes,
        String spoolObjectId,
        int pageCount,
        boolean color,
        Instant submittedAt,
        Instant holdUntil,
        JobState state,
        String releaseTokenHash,
        String releasedPrinterId,
        Instant releasedAt,
        String failureReason) {

    public PrintJob {
        collectSites = collectSites == null ? Set.of() : Set.copyOf(collectSites);
    }

    public PrintJob withState(JobState newState) {
        return new PrintJob(jobId, ownerEmployeeId, homeSiteId, collectSites, documentName,
                documentClass, sizeBytes, spoolObjectId, pageCount, color, submittedAt,
                holdUntil, newState, releaseTokenHash, releasedPrinterId, releasedAt,
                failureReason);
    }

    public PrintJob released(String printerId, Instant when) {
        return new PrintJob(jobId, ownerEmployeeId, homeSiteId, collectSites, documentName,
                documentClass, sizeBytes, spoolObjectId, pageCount, color, submittedAt,
                holdUntil, JobState.RELEASED, releaseTokenHash, printerId, when, null);
    }

    public PrintJob failed(String reason) {
        return new PrintJob(jobId, ownerEmployeeId, homeSiteId, collectSites, documentName,
                documentClass, sizeBytes, spoolObjectId, pageCount, color, submittedAt,
                holdUntil, JobState.FAILED, releaseTokenHash, releasedPrinterId, releasedAt,
                reason);
    }

    /**
     * Keeps the released/reconciled metadata but drops the spool reference and token hash, for use
     * once the document bytes have been destroyed. The record remains for audit; the ciphertext
     * does not remain anywhere.
     */
    public PrintJob withoutSpool() {
        return new PrintJob(jobId, ownerEmployeeId, homeSiteId, collectSites, documentName,
                documentClass, sizeBytes, "", pageCount, color, submittedAt, holdUntil, state,
                "", releasedPrinterId, releasedAt, failureReason);
    }

    /** Tombstone form: no spool reference, no token, nothing that could decrypt anything. */
    public PrintJob tombstone(JobState tombstoneState, String reason) {
        return new PrintJob(jobId, ownerEmployeeId, homeSiteId, collectSites, documentName,
                documentClass, 0, "", pageCount, color, submittedAt, holdUntil, tombstoneState,
                "", releasedPrinterId, releasedAt, reason);
    }

    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(holdUntil);
    }

    public boolean collectableAt(String siteId) {
        return collectSites.contains(siteId) || collectSites.contains(Employee.ANY_SITE);
    }
}
