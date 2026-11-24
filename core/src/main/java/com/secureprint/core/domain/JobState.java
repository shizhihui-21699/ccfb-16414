package com.secureprint.core.domain;

/** Lifecycle of a held job. Only {@link #RELEASED} jobs ever reach a printer. */
public enum JobState {
    /** Accepted, sealed, waiting for the owner to authenticate at a device. */
    HELD,
    /** Owner authenticated; the release agent is rendering and transmitting. */
    RELEASING,
    /** Fully printed. */
    RELEASED,
    /** Owner explicitly cancelled before release. */
    CANCELLED,
    /** Hold window elapsed; document bytes destroyed, only a tombstone record remains. */
    EXPIRED,
    /** Repeated delivery failure; requires operator attention. */
    FAILED,
    /**
     * An agent printed this job while disconnected and has not yet been reconciled with the
     * server. Not a terminal state: the reconciler either promotes it to RELEASED or, if the job
     * was cancelled/expired during the partition, records an incident and moves it to FAILED.
     */
    OFFLINE_UNCONFIRMED
}
