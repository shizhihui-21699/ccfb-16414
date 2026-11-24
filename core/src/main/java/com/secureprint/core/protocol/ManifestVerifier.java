package com.secureprint.core.protocol;

import com.secureprint.core.crypto.Ed25519;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Verifies and monotonicity-checks release manifests on an agent.
 *
 * <p>Beyond the signature, an agent must defend against a malicious or buggy peer replaying an
 * <em>older</em> manifest to re-enable a job that has since been cancelled. Two controls:
 * <ol>
 *   <li>{@code sequence} must strictly increase per agent — persisted across restarts.</li>
 *   <li>{@code expiresAt} must be in the future, and the agent additionally rejects manifests
 *       older than its configured max age, so a stale manifest captured last week cannot be
 *       replayed after a long outage.</li>
 * </ol>
 */
public final class ManifestVerifier {

    private final PublicKey serverKey;
    private final Clock clock;
    private final Duration maxAge;
    private long lastSequence = -1;

    public ManifestVerifier(PublicKey serverKey, Clock clock, Duration maxAge) {
        this.serverKey = serverKey;
        this.clock = clock;
        this.maxAge = maxAge;
    }

    public sealed interface Result permits Result.Accepted, Result.Rejected {
        record Accepted() implements Result {
        }

        record Rejected(String reason) implements Result {
        }
    }

    public Result verify(ReleaseManifest manifest, byte[] signature, String expectedAgentId) {
        if (!expectedAgentId.equals(manifest.agentId())) {
            return new Result.Rejected("manifest addressed to agent " + manifest.agentId());
        }
        byte[] canonical = GrantSigning.canonicalManifest(manifest);
        if (!Ed25519.verify(serverKey, canonical, signature)) {
            return new Result.Rejected("bad manifest signature");
        }
        Instant now = clock.instant();
        if (now.isBefore(manifest.notBefore())) {
            return new Result.Rejected("manifest not yet valid");
        }
        if (!now.isBefore(manifest.expiresAt())) {
            return new Result.Rejected("manifest expired");
        }
        if (manifest.issuedAt().isBefore(now.minus(maxAge))) {
            return new Result.Rejected("manifest older than max age " + maxAge);
        }
        if (manifest.sequence() <= lastSequence) {
            return new Result.Rejected("replayed manifest sequence " + manifest.sequence()
                    + " (last seen " + lastSequence + ")");
        }
        // Duplicate job ids in one manifest mean the server is confused; refuse rather than
        // guess which entry is authoritative.
        Set<String> seen = new HashSet<>();
        for (ReleaseManifest.Entry e : manifest.entries()) {
            if (!seen.add(e.jobId())) {
                return new Result.Rejected("duplicate job " + e.jobId() + " in manifest");
            }
        }
        lastSequence = manifest.sequence();
        return new Result.Accepted();
    }

    /** Restores persisted anti-replay state after an agent restart. */
    public void restoreSequence(long persistedSequence) {
        this.lastSequence = persistedSequence;
    }

    public long lastSequence() {
        return lastSequence;
    }

    public static byte[] sign(PrivateKey serverKey, ReleaseManifest manifest) {
        return Ed25519.sign(serverKey, GrantSigning.canonicalManifest(manifest));
    }

    public static byte[] sign(PrivateKey serverKey, ReleaseGrant grant) {
        return Ed25519.sign(serverKey, GrantSigning.canonicalGrant(grant));
    }
}
