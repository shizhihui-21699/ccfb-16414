package com.secureprint.server.config;

import com.secureprint.core.crypto.Ed25519;
import com.secureprint.core.util.Bytes;

import java.security.KeyPair;
import java.time.Duration;

/**
 * Installation-wide secrets and tunables.
 *
 * <p>In production every one of these comes from a KMS/HSM-backed secret store, never from a
 * file in the repo. The demo generates ephemeral values so nothing sensitive is ever committed.
 *
 * <p>{@code badgePepper} deserves special mention: badge UIDs are low-entropy (often 4-8 hex
 * bytes) and the same badge number may appear in other systems, so an unkeyed hash would be
 * rainbow-table-able. The pepper is what makes {@code badgeUidHash} safe to store.
 */
public record ServerConfig(
        byte[] masterSecret,
        byte[] badgePepper,
        KeyPair serverSigningKey,
        Duration defaultHoldTtl,
        Duration grantTtl,
        Duration manifestTtl,
        Duration manifestMaxAge,
        int maxDocumentBytes,
        int expirySweepBatch) {

    public static ServerConfig ephemeralDefaults() {
        return new ServerConfig(
                Bytes.random(32),
                Bytes.random(32),
                Ed25519.generate(),
                Duration.ofHours(8),
                Duration.ofMinutes(5),
                Duration.ofHours(24),
                Duration.ofHours(72),
                100 * 1024 * 1024,
                500);
    }

    public ServerConfig {
        if (masterSecret == null || masterSecret.length < 32) {
            throw new IllegalArgumentException("masterSecret must be >= 32 bytes");
        }
        if (badgePepper == null || badgePepper.length < 32) {
            throw new IllegalArgumentException("badgePepper must be >= 32 bytes");
        }
        if (maxDocumentBytes <= 0 || maxDocumentBytes > 1024L * 1024 * 1024) {
            throw new IllegalArgumentException("maxDocumentBytes out of range");
        }
    }
}
