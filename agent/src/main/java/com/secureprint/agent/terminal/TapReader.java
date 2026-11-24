package com.secureprint.agent.terminal;

import java.time.Instant;
import java.util.Optional;

/**
 * A badge/QR reader attached to a release printer (or a phone showing a QR code).
 *
 * <p>Readers are wildly inconsistent: some emit a UID as decimal, some as hex, some with a
 * trailing Enter, some as a keystroke stream from a keyboard-wedge reader. This interface hides
 * that, and — importantly — guarantees the <b>raw UID never leaves the reader boundary</b> in
 * any form other than what {@link com.secureprint.core.crypto.Hmac#badgeDigest} produces.
 */
public interface TapReader {

    record TapEvent(String rawUid, String printerId, Instant at, Kind kind) {
        public enum Kind {
            BADGE,
            QR
        }
    }

    /** Blocks until the next tap, or returns empty on timeout. */
    Optional<TapEvent> next(java.time.Duration timeout);

    /** Human-readable reader identity for audit ("terminal at 3F-Finance-east"). */
    String readerId();
}
