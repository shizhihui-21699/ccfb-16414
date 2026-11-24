package com.secureprint.core.audit;

import com.secureprint.core.util.Bytes;
import com.secureprint.core.util.Json;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

/**
 * Append-only, hash-chained audit log.
 *
 * <p>Not thread-safe by design: the caller serializes appends (a single writer goroutine in the
 * server). Reads may happen concurrently as long as the returned list is a snapshot.
 */
public final class AuditLog {

    private final Clock clock;
    private final AuditSink sink;
    private String lastHash = AuditEvent.GENESIS;
    private long lastSequence = -1;

    public AuditLog(Clock clock, AuditSink sink) {
        this.clock = clock;
        this.sink = sink;
    }

    public synchronized AuditEvent append(String actorEmployeeId, String role, String action,
                                          String jobId, String printerId, String siteId,
                                          String detail) {
        Instant now = clock.instant();
        long seq = lastSequence + 1;
        AuditEvent unsigned = new AuditEvent(seq, now, actorEmployeeId, role, action, jobId,
                printerId, siteId, detail, lastHash, null);
        String hash = Bytes.sha256Hex(Json.toCanonicalBytes(unsigned.toCanonicalFields()));
        AuditEvent event = new AuditEvent(seq, now, actorEmployeeId, role, action, jobId,
                printerId, siteId, detail, lastHash, hash);
        sink.write(event);
        lastHash = hash;
        lastSequence = seq;
        return event;
    }

    /** Replays a persisted chain at startup and returns the first broken sequence, if any. */
    public synchronized java.util.OptionalLong restore(List<AuditEvent> existing) {
        String prev = AuditEvent.GENESIS;
        long seq = -1;
        for (AuditEvent e : existing) {
            if (e.sequence() != seq + 1) {
                return java.util.OptionalLong.of(e.sequence());
            }
            if (!prev.equals(e.prevHash())) {
                return java.util.OptionalLong.of(e.sequence());
            }
            AuditEvent unsigned = new AuditEvent(e.sequence(), e.at(), e.actorEmployeeId(),
                    e.actorRole(), e.action(), e.jobId(), e.printerId(), e.siteId(), e.detail(),
                    e.prevHash(), null);
            String expected = Bytes.sha256Hex(
                    Json.toCanonicalBytes(unsigned.toCanonicalFields()));
            if (!expected.equals(e.hash())) {
                return java.util.OptionalLong.of(e.sequence());
            }
            prev = e.hash();
            seq = e.sequence();
        }
        this.lastHash = prev;
        this.lastSequence = seq;
        return java.util.OptionalLong.empty();
    }

    public static boolean verifyChain(List<AuditEvent> events) {
        String prev = AuditEvent.GENESIS;
        long seq = -1;
        for (AuditEvent e : events) {
            if (e.sequence() != seq + 1 || !prev.equals(e.prevHash())) {
                return false;
            }
            AuditEvent unsigned = new AuditEvent(e.sequence(), e.at(), e.actorEmployeeId(),
                    e.actorRole(), e.action(), e.jobId(), e.printerId(), e.siteId(), e.detail(),
                    e.prevHash(), null);
            String expected = Bytes.sha256Hex(
                    Json.toCanonicalBytes(unsigned.toCanonicalFields()));
            if (!expected.equals(e.hash())) {
                return false;
            }
            prev = e.hash();
            seq = e.sequence();
        }
        return true;
    }

    public synchronized String lastHash() {
        return lastHash;
    }
}
