package com.secureprint.server;

import com.secureprint.core.domain.JobState;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.server.service.ExpirySweeper;
import com.secureprint.server.service.ReleaseService;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExpirySweeperTest extends ServerTestBase {

    @Test
    void expiredJobIsDestroyedAndTombstoned() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        String submitted = submit("emp-1", "secret payroll",
                Duration.ofMinutes(30));
        PrintJob before = store.job(jobId(submitted)).orElseThrow();
        assertTrue(spool.exists(before.spoolObjectId()));

        moveClockTo(NOW.plus(Duration.ofHours(2)));
        ExpirySweeper.SweepResult result = sweeper.sweep();

        assertEquals(1, result.destroyed());
        PrintJob after = store.job(jobId(submitted)).orElseThrow();
        assertEquals(JobState.EXPIRED, after.state());
        assertEquals("", after.spoolObjectId(), "spool reference must be cleared");
        assertEquals(0, after.sizeBytes());
        assertFalse(spool.exists(before.spoolObjectId()),
                "spool bytes must be physically deleted");
        assertTrue(after.failureReason().contains("hold window elapsed"));
        assertEquals(1, auditEvents.size());
        assertTrue(auditEvents.get(0).startsWith("JOB_EXPIRED_DESTROYED|"));
    }

    @Test
    void releasedJobIsNeverSwept() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "paid", Duration.ofMinutes(30));
        releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh", "prn-sh-1");
        releases.confirmReleased("agent-sh", jobId(submitted));

        moveClockTo(NOW.plus(Duration.ofDays(2)));
        assertEquals(0, sweeper.sweep().destroyed());
        assertEquals(JobState.RELEASED, store.job(jobId(submitted)).orElseThrow().state());
    }

    @Test
    void heldJobInsideWindowSurvives() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        submit("emp-1", "still valid", Duration.ofHours(8));
        moveClockTo(NOW.plus(Duration.ofHours(1)));
        assertEquals(0, sweeper.sweep().destroyed());
    }

    @Test
    void cancellingClearsAccessEvenBeforeSweep() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        printer("prn-sh-1", SITE_SH, false);
        agent("agent-sh", SITE_SH);
        String submitted = submit("emp-1", "x");
        assertTrue(releases.cancel(jobId(submitted), "emp-1"));
        assertThrows(ReleaseService.ReleaseDenied.class, () ->
                releases.release(jobId(submitted), "emp-1", token(submitted), "agent-sh",
                        "prn-sh-1"));
    }

    @Test
    void sweepIsIdempotent() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        submit("emp-1", "x", Duration.ofMinutes(5));
        moveClockTo(NOW.plus(Duration.ofHours(1)));
        assertEquals(1, sweeper.sweep().destroyed());
        assertEquals(0, sweeper.sweep().destroyed(),
                "a second sweep must not double-count or fail");
    }

    @Test
    void parallelSweepsDestroyExactlyOnce() throws Exception {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        for (int i = 0; i < 20; i++) {
            submit("emp-1", "doc-" + i, Duration.ofMinutes(5));
        }
        moveClockTo(NOW.plus(Duration.ofHours(1)));

        var pool = java.util.concurrent.Executors.newFixedThreadPool(8);
        List<java.util.concurrent.Future<Integer>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < 8; i++) {
            futures.add(pool.submit(() -> sweeper.sweep().destroyed()));
        }
        int total = 0;
        for (var f : futures) {
            total += f.get(10, java.util.concurrent.TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertEquals(20, total, "each job destroyed exactly once across concurrent sweeps");
    }

    @Test
    void orphanSpoolObjectsArePurged() {
        employee("emp-1", "A1B2C3D4", SITE_SH);
        submit("emp-1", "x");
        spool.put("obj-orphan", new byte[]{1, 2, 3});
        assertEquals(1, sweeper.purgeOrphans(List.of("obj-orphan")));
        assertFalse(spool.exists("obj-orphan"));
    }
}
