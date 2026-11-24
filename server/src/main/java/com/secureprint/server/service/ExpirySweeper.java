package com.secureprint.server.service;

import com.secureprint.core.domain.JobState;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.core.store.SpoolStore;
import com.secureprint.server.store.JobStore;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

/**
 * Destroys documents whose hold window has elapsed.
 *
 * <p>Destruction is real, not cosmetic:
 * <ol>
 *   <li>The sealed spool blob is deleted from the blob store.</li>
 *   <li>The job record is rewritten as {@link JobState#EXPIRED} with the spool object id
 *       cleared, keeping only a tombstone (who, what class, when, why) for audit.</li>
 * </ol>
 *
 * <p>Because each job is sealed under its own data key which is wrapped inside that same blob,
 * deleting the blob is equivalent to crypto-shredding the document: even a filesystem snapshot
 * or backup of the volume from an earlier time would contain a wrapped key whose KEK-wrapped
 * copy is gone. There is no "undelete" path.
 *
 * <p>Runs on a scheduler (see {@code ScheduledExecutor}) and is idempotent: two sweeps racing
 * over the same job will both observe it as EXPIRED and the second delete is a no-op.
 */
public final class ExpirySweeper {

    private final JobStore store;
    private final SpoolStore spool;
    private final Clock clock;
    private final int batchSize;
    private final AuditRecorder audit;

    public ExpirySweeper(JobStore store, SpoolStore spool, Clock clock, int batchSize,
                         AuditRecorder audit) {
        this.store = store;
        this.spool = spool;
        this.clock = clock;
        this.batchSize = batchSize;
        this.audit = audit;
    }

    /** Minimal audit seam so the sweeper does not depend on the full AuditLog wiring. */
    public interface AuditRecorder {
        void record(String action, String jobId, String actorEmployeeId, String detail);
    }

    public record SweepResult(int destroyed, int scanned) {
    }

    public synchronized SweepResult sweep() {
        Instant now = clock.instant();
        List<PrintJob> due = store.expiredJobs(now, batchSize);
        int destroyed = 0;
        for (PrintJob job : due) {
            // Winning the atomic transition is what grants the right to destroy. A release that
            // claimed the job a nanosecond ago makes this return empty and the job survives.
            PrintJob current = store.claimExpired(job.jobId(), now).orElse(null);
            if (current == null) {
                continue;
            }
            spool.delete(current.spoolObjectId());
            store.saveJob(current.tombstone(JobState.EXPIRED,
                    "hold window elapsed at " + current.holdUntil()));
            audit.record("JOB_EXPIRED_DESTROYED", current.jobId(), current.ownerEmployeeId(),
                    "hold window elapsed");
            destroyed++;
        }
        return new SweepResult(destroyed, due.size());
    }

    /** Startup integrity check: spool objects with no live job are orphans and get removed. */
    public int purgeOrphans(List<String> objectIdsOnDisk) {
        int removed = 0;
        for (String objectId : objectIdsOnDisk) {
            boolean referenced = store.allJobs().stream()
                    .anyMatch(j -> objectId.equals(j.spoolObjectId())
                            && j.state() != JobState.EXPIRED && j.state() != JobState.CANCELLED
                            && j.state() != JobState.FAILED);
            if (!referenced) {
                spool.delete(objectId);
                removed++;
            }
        }
        return removed;
    }

}
