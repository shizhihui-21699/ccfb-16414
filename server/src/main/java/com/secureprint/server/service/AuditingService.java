package com.secureprint.server.service;

import com.secureprint.core.audit.AuditEvent;
import com.secureprint.core.audit.AuditLog;
import com.secureprint.core.audit.AuditSink;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * Wraps {@link AuditLog} and gives the services a coarse, typed vocabulary of audit actions.
 *
 * <p>Two deliberate choices:
 * <ul>
 *   <li><b>No document content ever enters the audit trail.</b> The detail field carries the job
 *       id, the printer, the site and the outcome, never the file name of a payroll item or any
 *       bytes. An audit trail that leaks what it audits is a liability under GDPR/个保法.</li>
 *   <li><b>Failed releases are audited too.</b> "Someone tried to print Wang's payslip at a
 *       Suzhou printer and was refused" is exactly the signal a DLP/insider-threat review needs.</li>
 * </ul>
 */
public final class AuditingService {

    private final AuditLog log;
    private final List<AuditEvent> mirror;

    public AuditingService(Clock clock, AuditSink sink) {
        this.mirror = new ArrayList<>();
        AuditSink tee = event -> {
            synchronized (mirror) {
                mirror.add(event);
            }
            sink.write(event);
        };
        this.log = new AuditLog(clock, tee);
    }

    public enum Action {
        JOB_SUBMITTED,
        BADGE_AUTH_OK,
        BADGE_AUTH_FAILED,
        RELEASE_GRANTED,
        RELEASE_DENIED,
        RELEASE_CONFIRMED,
        RELEASE_FAILED,
        JOB_CANCELLED,
        JOB_EXPIRED_DESTROYED,
        MANIFEST_ISSUED,
        AGENT_ENROLLED,
        OFFLINE_RELEASE_UNCONFIRMED
    }

    public void record(Action action, String actorEmployeeId, String role, String jobId,
                       String printerId, String siteId, String detail) {
        log.append(actorEmployeeId, role, action.name(), jobId, printerId, siteId, detail);
    }

    public List<AuditEvent> snapshot() {
        synchronized (mirror) {
            return List.copyOf(mirror);
        }
    }

    public boolean verifyChain() {
        synchronized (mirror) {
            return AuditLog.verifyChain(mirror);
        }
    }

    public String lastHash() {
        return log.lastHash();
    }
}
