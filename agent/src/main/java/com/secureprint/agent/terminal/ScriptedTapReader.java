package com.secureprint.agent.terminal;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;

/**
 * Scriptable reader used by the demo and by tests. Real deployments bind this interface to a
 * PC/SC reader, an HID keyboard-wedge reader, or a phone camera QR scanner.
 */
public final class ScriptedTapReader implements TapReader {

    private final String readerId;
    private final Deque<TapEvent> events = new ArrayDeque<>();

    public ScriptedTapReader(String readerId) {
        this.readerId = readerId;
    }

    public void tapBadge(String rawUid, String printerId) {
        events.add(new TapEvent(rawUid, printerId, java.time.Instant.now(), TapEvent.Kind.BADGE));
    }

    public void tapQr(String payload, String printerId) {
        events.add(new TapEvent(payload, printerId, java.time.Instant.now(), TapEvent.Kind.QR));
    }

    @Override
    public Optional<TapEvent> next(Duration timeout) {
        synchronized (events) {
            return Optional.ofNullable(events.poll());
        }
    }

    @Override
    public String readerId() {
        return readerId;
    }
}
