package com.secureprint.core.audit;

import com.secureprint.core.util.Bytes;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditLogTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-11-25T10:00:00Z"), ZoneOffset.UTC);

    @Test
    void chainLinksAndVerifies() {
        AuditLog log = new AuditLog(CLOCK, e -> { });
        log.append("emp-1", "EMPLOYEE", "JOB_SUBMITTED", "job-1", null, "site-a", "payslip");
        log.append("emp-1", "EMPLOYEE", "JOB_RELEASED", "job-1", "prn-3", "site-b", "badge");
        assertFalse(log.lastHash().equals(AuditEvent.GENESIS));
    }

    @Test
    void tamperingBreaksVerification() {
        List<AuditEvent> store = new ArrayList<>();
        AuditLog log = new AuditLog(CLOCK, store::add);
        log.append("emp-1", "EMPLOYEE", "SUBMIT", "job-1", null, "a", null);
        log.append("emp-1", "EMPLOYEE", "RELEASE", "job-1", "p1", "a", null);
        log.append("emp-1", "EMPLOYEE", "EXPIRE", "job-1", null, "a", null);
        assertTrue(AuditLog.verifyChain(store));

        AuditEvent original = store.get(1);
        store.set(1, new AuditEvent(original.sequence(), original.at(),
                original.actorEmployeeId(), original.actorRole(), original.action(),
                original.jobId(), original.printerId(), original.siteId(),
                "tampered detail", original.prevHash(), original.hash()));
        assertFalse(AuditLog.verifyChain(store));
    }

    @Test
    void deletedRecordBreaksVerification() {
        List<AuditEvent> store = new ArrayList<>();
        AuditLog log = new AuditLog(CLOCK, store::add);
        log.append("e", "R", "A1", "j", null, "s", null);
        log.append("e", "R", "A2", "j", null, "s", null);
        log.append("e", "R", "A3", "j", null, "s", null);
        store.remove(1);
        assertFalse(AuditLog.verifyChain(store));
    }

    @Test
    void restoreContinuesChain() {
        List<AuditEvent> store = new ArrayList<>();
        AuditLog log = new AuditLog(CLOCK, store::add);
        log.append("e", "R", "A1", "j", null, "s", null);
        log.append("e", "R", "A2", "j", null, "s", null);
        String lastHash = log.lastHash();

        AuditLog restarted = new AuditLog(CLOCK, store::add);
        assertTrue(restarted.restore(store).isEmpty());
        assertEquals(lastHash, restarted.lastHash());
        AuditEvent next = restarted.append("e", "R", "A3", "j", null, "s", null);
        assertEquals(2, next.sequence());
        assertEquals(lastHash, next.prevHash());
        assertTrue(AuditLog.verifyChain(store));
    }

    @Test
    void restoreDetectsBrokenChain() {
        List<AuditEvent> store = new ArrayList<>();
        AuditLog log = new AuditLog(CLOCK, store::add);
        log.append("e", "R", "A1", "j", null, "s", null);
        log.append("e", "R", "A2", "j", null, "s", null);
        store.remove(0);
        AuditLog restarted = new AuditLog(CLOCK, store::add);
        assertTrue(restarted.restore(store).isPresent());
    }

    @Test
    void genesisUsedForFirstRecord() {
        List<AuditEvent> store = new ArrayList<>();
        new AuditLog(CLOCK, store::add).append("e", "R", "A1", "j", null, "s", null);
        assertEquals(AuditEvent.GENESIS, store.get(0).prevHash());
        assertEquals(64, store.get(0).hash().length());
    }
}
