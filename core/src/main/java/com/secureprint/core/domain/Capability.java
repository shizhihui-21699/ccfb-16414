package com.secureprint.core.domain;

/** Coarse printer capabilities so the scheduler never routes a job at a device that cannot render it. */
public enum Capability {
    MONO,
    COLOR,
    DUPLEX,
    STAPLE,
    A3,
    A4,
    LARGE_FORMAT,
    CARD_READER,
    QR_SCANNER,
    RELEASE_TERMINAL
}
