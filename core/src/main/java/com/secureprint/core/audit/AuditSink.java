package com.secureprint.core.audit;

/** Append-only persistence for audit events (usually an insert-only table or WORM volume). */
public interface AuditSink {

    void write(AuditEvent event);
}
