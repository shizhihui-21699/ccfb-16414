package com.secureprint.server;

import com.secureprint.core.domain.JobState;
import com.secureprint.core.protocol.ReleaseGrant;
import com.secureprint.server.service.ReleaseService;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OfflineGrantTest extends ServerTestBase {

    @Test
    void offlineGrantDoesNotClaimTheJob() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");

        var grant = releases.issueOfflineGrant(jobId(submitted), "emp-1", "agent-sh",
                "prn-sh-1");
        assertEquals(ReleaseGrant.Mode.OFFLINE, grant.grant().mode());
        assertEquals(JobState.HELD, store.job(jobId(submitted)).orElseThrow().state(),
                "offline grant must not consume the job: an online release may still happen");
    }

    @Test
    void offlineGrantNeverOutlivesTheJobHoldWindow() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello", Duration.ofMinutes(20));
        var job = store.job(jobId(submitted)).orElseThrow();

        var grant = releases.issueOfflineGrant(jobId(submitted), "emp-1", "agent-sh",
                "prn-sh-1");
        assertTrue(!grant.grant().expiresAt().isAfter(job.holdUntil()),
                "an offline grant must not outlive the document's own hold deadline");
    }

    @Test
    void offlineGrantRejectsWrongSite() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-muc", SITE_MUC, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");
        assertThrows(ReleaseService.ReleaseDenied.class, () ->
                releases.issueOfflineGrant(jobId(submitted), "emp-1", "agent-sh", "prn-muc"));
    }

    @Test
    void offlineGrantRejectsStrangers() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        employee("emp-2", "BBBB0001", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");
        assertThrows(ReleaseService.ReleaseDenied.class, () ->
                releases.issueOfflineGrant(jobId(submitted), "emp-2", "agent-sh", "prn-sh-1"));
    }

    @Test
    void reconcilePromotesHeldJobToReleased() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        String submitted = submit("emp-1", "hello");
        var verdict = releases.reconcileOffline("agent-sh", jobId(submitted), true, "printed");
        assertEquals(ReleaseService.ReconcileResult.CONFIRMED, verdict);
        assertEquals(JobState.RELEASED, store.job(jobId(submitted)).orElseThrow().state());
    }

    @Test
    void reconcileFlagsPrintedAfterCancel() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        String submitted = submit("emp-1", "hello");
        releases.cancel(jobId(submitted), "emp-1");

        var verdict = releases.reconcileOffline("agent-sh", jobId(submitted), true, "printed");
        assertEquals(ReleaseService.ReconcileResult.PRINTED_AFTER_CANCEL, verdict);
        var job = store.job(jobId(submitted)).orElseThrow();
        assertEquals(JobState.FAILED, job.state());
        assertTrue(job.failureReason().contains("after cancellation"),
                "the trail must say what actually happened, not erase it");
    }

    @Test
    void reconcileFlagsDoublePrint() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "hello");
        releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh", "prn-sh-1");
        releases.confirmReleased("agent-sh", jobId(submitted));

        var verdict = releases.reconcileOffline("agent-offline", jobId(submitted), true, "x");
        assertEquals(ReleaseService.ReconcileResult.ALREADY_RELEASED_DOUBLE_PRINT, verdict);
    }

    @Test
    void reconcileRevertsFailedOfflineAttempt() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        String submitted = submit("emp-1", "hello");
        var verdict = releases.reconcileOffline("agent-sh", jobId(submitted), false, "jam");
        assertEquals(ReleaseService.ReconcileResult.REVERTED_TO_HELD, verdict);
        assertEquals(JobState.HELD, store.job(jobId(submitted)).orElseThrow().state());
    }

    @Test
    void reconcileUnknownJobIsReported() {
        assertEquals(ReleaseService.ReconcileResult.UNKNOWN_JOB,
                releases.reconcileOffline("agent-sh", "job-nope", true, "x"));
    }

    @Test
    void travellingEmployeeJobIsCollectableAtBothSites() {
        var e = new com.secureprint.core.domain.Employee("emp-t", "Traveler", "Sales", "t@x",
                "hash", SITE_SH, java.util.Set.of(SITE_MUC), true, NOW);
        store.saveEmployee(e);
        assertTrue(e.canCollectAt(SITE_SH));
        assertTrue(e.canCollectAt(SITE_MUC));
        assertTrue(!e.canCollectAt("site-beijing"));
    }
}
