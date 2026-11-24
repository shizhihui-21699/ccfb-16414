package com.secureprint.server;

import com.secureprint.core.domain.JobState;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.server.service.ReleaseService;
import com.secureprint.server.service.SubmissionService;
import com.secureprint.server.store.InMemoryJobStore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
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

class ReleaseFlowTest extends ServerTestBase {

    private static PrintJob held(String id, String owner) {
        return new PrintJob(id, owner, "site-shanghai", java.util.Set.of("site-shanghai"),
                "p.pdf", "PAYROLL", 10, "obj-" + id, 0,
                false, NOW, NOW.plus(8, ChronoUnit.HOURS), JobState.HELD, "hash", null, null, null);
    }

    // ---------- submission ----------

    @Test
    void submissionSealsDocumentAndReturnsOneTimeToken() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        String submitted = submit("emp-1", "NET PAY 12345");
        String jobId = jobId(submitted);

        PrintJob job = store.job(jobId).orElseThrow();
        assertEquals(JobState.HELD, job.state());
        assertEquals("emp-1", job.ownerEmployeeId());
        assertTrue(job.sizeBytes() > 0);
        assertFalse(job.releaseTokenHash().contains(token(submitted)),
                "stored hash must not contain the raw token");
        assertTrue(spool.exists(job.spoolObjectId()));
    }

    @Test
    void submittedBytesAreEncryptedOnDisk() throws Exception {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        String submitted = submit("emp-1", "SALARY=998877");
        PrintJob job = store.job(jobId(submitted)).orElseThrow();

        byte[] onDisk = spool.get(job.spoolObjectId()).orElseThrow();
        String asIso = new String(onDisk, java.nio.charset.StandardCharsets.ISO_8859_1);
        assertFalse(asIso.contains("SALARY"), "plaintext must never hit the spool store");
        assertFalse(asIso.contains("998877"));
    }

    @Test
    void submissionRejectsUnknownOrInactiveEmployee() {
        assertThrows(SubmissionService.SubmissionRejected.class, () -> submit("ghost", "x"));
        store.saveEmployee(new com.secureprint.core.domain.Employee(
                "emp-off", "Off", "d", "e", "hash", SITE_SH, false, NOW));
        assertThrows(SubmissionService.SubmissionRejected.class, () -> submit("emp-off", "x"));
    }

    @Test
    void submissionRejectsEmptyAndOversizedDocuments() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        assertThrows(SubmissionService.SubmissionRejected.class, () -> submit("emp-1", ""));
        byte[] huge = new byte[config.maxDocumentBytes() + 1];
        assertThrows(SubmissionService.SubmissionRejected.class, () ->
                submissions.submit(new SubmissionService.SubmitRequest("emp-1", "big.pdf",
                        "application/pdf", huge, 1, null, null, null, List.of(), "GENERAL",
                        null)));
    }

    // ---------- online release ----------

    @Test
    void badgeAuthenticationFindsPendingJobsOnly() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        submit("emp-1", "one");
        String s2 = submit("emp-1", "two");
        releases.cancel(jobId(s2), "emp-1");

        var outcome = releases.authenticateBadge("A1B2C3D4").orElseThrow();
        assertEquals("emp-1", outcome.employeeId());
        assertEquals(1, outcome.pending().size());
    }

    @Test
    void badgeLookupFailsForUnknownBadge() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        assertTrue(releases.authenticateBadge("DEADBEEF").isEmpty());
    }

    @Test
    void releaseProducesVerifiableGrantBoundToAgentAndPrinter() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");

        var grant = releases.release(jobId(submitted), "emp-1", token(submitted),
                "agent-sh", "prn-sh-1");

        assertEquals(JobState.RELEASING, store.job(jobId(submitted)).orElseThrow().state());
        assertEquals("emp-1", grant.grant().employeeId());
        assertEquals("agent-sh", grant.grant().agentId());
        assertEquals("prn-sh-1", grant.grant().printerId());
        assertTrue(releases.verifyGrant(grant,
                com.secureprint.core.util.Bytes.unb64url(grant.signatureB64())));
        assertFalse(grant.grant().jobDataKeyWrapped().isBlank());
    }

    @Test
    void releaseRequiresTheMatchingToken() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");

        assertThrows(ReleaseService.ReleaseDenied.class, () ->
                releases.release(jobId(submitted), "emp-1", "wrong-token", "agent-sh",
                        "prn-sh-1"));
        assertEquals(JobState.HELD, store.job(jobId(submitted)).orElseThrow().state(),
                "a refused release must leave the job held");
    }

    @Test
    void strangerCannotReleaseSomeoneElsesJob() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        employee("emp-2", "EEEE0001", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");

        assertThrows(ReleaseService.ReleaseDenied.class, () ->
                releases.release(jobId(submitted), "emp-2", token(submitted), "agent-sh",
                        "prn-sh-1"));
    }

    @Test
    void grantIsSingleUse() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");

        releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh", "prn-sh-1");
        assertThrows(ReleaseService.ReleaseDenied.class, () ->
                releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh",
                        "prn-sh-1"));
    }

    @Test
    void concurrentReleasesAtTwoPrintersYieldExactlyOneWinner() throws Exception {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-a", SITE_SH, false);
        printer("prn-b", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger wins = new AtomicInteger();
        AtomicInteger denials = new AtomicInteger();
        List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            String printerId = i % 2 == 0 ? "prn-a" : "prn-b";
            futures.add(pool.submit(() -> {
                start.await();
                try {
                    releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh",
                            printerId);
                    wins.incrementAndGet();
                } catch (ReleaseService.ReleaseDenied e) {
                    denials.incrementAndGet();
                }
                return null;
            }));
        }
        start.countDown();
        for (var f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertEquals(1, wins.get(), "exactly one release may win");
        assertEquals(threads - 1, denials.get());
    }

    @Test
    void colourJobRejectedOnMonochromePrinter() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-mono", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        var sub = submissions.submit(new SubmissionService.SubmitRequest("emp-1", "c.pdf",
                "application/pdf", "%PDF-1.4 colour".getBytes(), 1,
                com.secureprint.core.domain.ColorMode.COLOR,
                com.secureprint.core.domain.DuplexMode.SIMPLEX,
                com.secureprint.core.domain.PaperSize.A4, List.of(), "CONTRACT", null));

        assertThrows(ReleaseService.ReleaseDenied.class, () ->
                releases.release(sub.jobId(), "emp-1", sub.releaseToken(), "agent-sh",
                        "prn-mono"));
    }

    @Test
    void agentCannotDrivePrinterAtAnotherSite() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-muc-1", SITE_MUC, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");

        assertThrows(ReleaseService.ReleaseDenied.class, () ->
                releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh",
                        "prn-muc-1"));
    }

    @Test
    void expiredJobCannotBeReleased() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello",
                java.time.Duration.ofMinutes(30));

        moveClockTo(NOW.plus(java.time.Duration.ofHours(1)));
        assertThrows(ReleaseService.ReleaseDenied.class, () ->
                releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh",
                        "prn-sh-1"));
    }

    @Test
    void confirmedReleaseDestroysTheSpoolBlob() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");
        String objectId = store.job(jobId(submitted)).orElseThrow().spoolObjectId();
        assertTrue(spool.exists(objectId));

        releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh", "prn-sh-1");
        releases.confirmReleased("agent-sh", jobId(submitted));

        assertFalse(spool.exists(objectId),
                "a printed document must not remain decryptable on the server");
        PrintJob job = store.job(jobId(submitted)).orElseThrow();
        assertEquals(JobState.RELEASED, job.state());
        assertEquals("", job.spoolObjectId());
        assertEquals("", job.releaseTokenHash(), "a used token must not stay in the record");
    }

    @Test
    void cancelDestroysTheSpoolBlobImmediately() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        String submitted = submit("emp-1", "hello");
        String objectId = store.job(jobId(submitted)).orElseThrow().spoolObjectId();

        assertTrue(releases.cancel(jobId(submitted), "emp-1"));
        assertFalse(spool.exists(objectId), "cancelling must destroy the bytes, not just hide them");
        assertEquals("", store.job(jobId(submitted)).orElseThrow().spoolObjectId());
    }

    @Test
    void lastPageOfReleasedJobIsNotServableFromTheStore() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "very secret");
        releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh", "prn-sh-1");
        releases.confirmReleased("agent-sh", jobId(submitted));

        // Nothing in the store refers to a live ciphertext any more.
        assertTrue(store.allJobs().stream()
                        .filter(j -> j.state() == JobState.RELEASED)
                        .allMatch(j -> j.spoolObjectId().isEmpty()),
                "no released job may retain a spool reference");
    }

    @Test
    void confirmReleaseMarksJobReleased() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");
        releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh", "prn-sh-1");

        releases.confirmReleased("agent-sh", jobId(submitted));
        assertEquals(JobState.RELEASED, store.job(jobId(submitted)).orElseThrow().state());
    }

    // ---------- cancellation ----------

    @Test
    void ownerCanCancelAndStrangerCannot() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        employee("emp-2", "EEEE0001", SITE_SH);
        String submitted = submit("emp-1", "hello");

        assertFalse(releases.cancel(jobId(submitted), "emp-2"));
        assertTrue(releases.cancel(jobId(submitted), "emp-1"));
        assertEquals(JobState.CANCELLED, store.job(jobId(submitted)).orElseThrow().state());
    }

    // ---------- in-memory store contract ----------

    @Test
    void storeClaimIsAtomicAndOwnerScoped() {
        InMemoryJobStore s = new InMemoryJobStore();
        s.saveJob(held("j1", "emp-1"));
        assertTrue(s.claimForRelease("j1", "emp-1", NOW));
        assertFalse(s.claimForRelease("j1", "emp-1", NOW));
        assertFalse(s.claimForRelease("j1", "emp-2", NOW));
    }

    @Test
    void storeClaimRefusesExpiredJobs() {
        InMemoryJobStore s = new InMemoryJobStore();
        s.saveJob(held("j1", "emp-1"));
        assertFalse(s.claimForRelease("j1", "emp-1", NOW.plus(9, ChronoUnit.HOURS)));
    }
}
