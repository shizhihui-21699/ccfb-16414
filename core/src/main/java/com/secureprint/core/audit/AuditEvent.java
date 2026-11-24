package com.secureprint.core.audit;

import java.time.Instant;
import java.util.Map;

/**
 * One tamper-evident audit record.
 *
 * <p>{@code prevHash} links to the previous record's {@code hash}; any edit to history breaks
 * every later link. Auditors (or the nightly integrity sweep) can re-walk the chain and report
 * the first divergence. This matters for payroll/contract documents: after a data-protection
 * complaint you need to show exactly who released what, where, and when.
 */
public record AuditEvent(
        long sequence,
        Instant at,
        String actorEmployeeId,
        String actorRole,
        String action,
        String jobId,
        String printerId,
        String siteId,
        String detail,
        String prevHash,
        String hash) {

    public static final String GENESIS = "0".repeat(64);

    public AuditEvent {
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("audit action required");
        }
    }

    public Map<String, Object> toCanonicalFields() {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("sequence", sequence);
        m.put("at", at.toString());
        m.put("actorEmployeeId", actorEmployeeId == null ? "" : actorEmployeeId);
        m.put("actorRole", actorRole == null ? "" : actorRole);
        m.put("action", action);
        m.put("jobId", jobId == null ? "" : jobId);
        m.put("printerId", printerId == null ? "" : printerId);
        m.put("siteId", siteId == null ? "" : siteId);
        m.put("detail", detail == null ? "" : detail);
        m.put("prevHash", prevHash);
        return m;
    }
}
