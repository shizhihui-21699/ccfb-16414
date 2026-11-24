package com.secureprint.agent;

import com.secureprint.agent.sync.OfflineJournal;
import com.secureprint.agent.sync.OfflineReconciler;
import com.secureprint.core.domain.JobState;
import com.secureprint.server.service.ReleaseService;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reconciliation behaviour: the bridge between "the branch printed it" and "the server's records
 * say so". These tests exist because this is where an offline printing system most easily starts
 * lying in its audit trail.
 */
class OfflineJournalTest {

    private static final Instant NOW = Instant.parse("2026-11-25T10:00:00Z");

    private OfflineJournal journal(Path dir) {
        return new OfflineJournal(dir.resolve("journal.ndjson"));
    }

    @Test
    void appendIsIdempotentPerJob() throws Exception {
        Path dir = Files.createTempDirectory("journal");
        OfflineJournal j = journal(dir);
        OfflineJournal.Entry e = new OfflineJournal.Entry("job-1", "emp-1", "prn-1", "g-1",
                NOW, "IN_PROGRESS", "started");
        assertTrue(j.appendAttempt(e));
        assertFalse(j.appendAttempt(e), "second append for same job must be refused");
        assertEquals(1, j.pending().size());
    }

    @Test
    void outcomeUpdateRewritesInPlace() throws Exception {
        Path dir = Files.createTempDirectory("journal");
        OfflineJournal j = journal(dir);
        j.appendAttempt(new OfflineJournal.Entry("job-1", "emp-1", "prn-1", "g-1", NOW,
                "IN_PROGRESS", "started"));
        j.updateOutcome("job-1", "DELIVERED", "device accepted");
        assertEquals("DELIVERED", j.pending().get(0).outcome());
    }

    @Test
    void acknowledgementRemovesOnlyConfirmedJobs() throws Exception {
        Path dir = Files.createTempDirectory("journal");
        OfflineJournal j = journal(dir);
        for (int i = 0; i < 3; i++) {
            j.appendAttempt(new OfflineJournal.Entry("job-" + i, "emp-1", "prn-1", "g", NOW,
                    "DELIVERED", "ok"));
        }
        j.acknowledge(java.util.List.of("job-0", "job-2"));
        assertEquals(1, j.pending().size());
        assertEquals("job-1", j.pending().get(0).jobId());
    }

    @Test
    void tornFinalLineIsSkippedNotFatal() throws Exception {
        Path dir = Files.createTempDirectory("journal");
        Path file = dir.resolve("journal.ndjson");
        OfflineJournal j = new OfflineJournal(file);
        j.appendAttempt(new OfflineJournal.Entry("job-1", "emp-1", "prn-1", "g", NOW,
                "DELIVERED", "ok"));
        Files.writeString(file, "\n{\"jobId\":\"job-2\",\"trunc",
                java.nio.file.StandardOpenOption.APPEND);
        assertEquals(1, j.pending().size(),
                "a crash-torn line must not lose the intact entries");
    }

    @Test
    void unknownOutcomeIsOneIncidentNotAFabricatedSuccess() throws Exception {
        Path dir = Files.createTempDirectory("journal");
        OfflineJournal j = journal(dir);
        j.appendAttempt(new OfflineJournal.Entry("job-x", "emp-1", "prn-1", "g", NOW,
                "IN_PROGRESS", "agent died mid-delivery"));

        java.util.List<String> verdicts = new java.util.ArrayList<>();
        OfflineReconciler r = new OfflineReconciler("agent-1", j, (agent, job, delivered, d) -> {
            verdicts.add("delivered=" + delivered + " detail=" + d);
            return new OfflineReconciler.Result("CONFIRMED", d);
        });
        var summary = r.replay();
        assertEquals(1, summary.incidents());
        assertTrue(verdicts.get(0).contains("outcome unknown"),
                "must report ambiguity rather than assume success");
    }

    @Test
    void failedOfflinePrintIsRevertedToHeld() throws Exception {
        Path dir = Files.createTempDirectory("journal");
        OfflineJournal j = journal(dir);
        j.appendAttempt(new OfflineJournal.Entry("job-f", "emp-1", "prn-1", "g", NOW,
                "FAILED", "printer jam"));

        java.util.concurrent.atomic.AtomicBoolean sawDelivered =
                new java.util.concurrent.atomic.AtomicBoolean(true);
        OfflineReconciler r = new OfflineReconciler("agent-1", j, (agent, job, delivered, d) -> {
            sawDelivered.set(delivered);
            return new OfflineReconciler.Result("REVERTED_TO_HELD", d);
        });
        r.replay();
        assertFalse(sawDelivered.get(), "a FAILED entry must be reported as not delivered");
        assertTrue(j.pending().isEmpty(), "acknowledged entries are removed");
    }
}
