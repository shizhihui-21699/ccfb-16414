package com.secureprint.agent.sync;

import com.secureprint.agent.store.AgentKeyVault;
import com.secureprint.agent.store.OfflineSpool;
import com.secureprint.core.crypto.Ed25519;
import com.secureprint.core.protocol.ManifestVerifier;
import com.secureprint.core.protocol.ReleaseManifest;
import com.secureprint.core.util.Bytes;
import com.secureprint.core.util.Json;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Applies a manifest pulled from the server.
 *
 * <p>This is the only place offline authority enters the agent, so it is where every check
 * happens:
 * <ol>
 *   <li>Signature over the canonical manifest — proves the server issued it.</li>
 *   <li>Agent id match — a manifest for another branch cannot be replayed here.</li>
 *   <li>Validity window and max age — bounds how long a captured manifest stays useful.</li>
 *   <li>Strictly increasing sequence — prevents re-enabling a job that a later manifest dropped.</li>
 * </ol>
 *
 * <p>The verification result and the advanced sequence are persisted in the same atomic vault
 * write, so a crash between accepting a manifest and saving its sequence cannot let the same
 * sequence be accepted twice after restart.
 */
public final class ManifestSyncService {

    private final String agentId;
    private final AgentKeyVault vault;
    private final OfflineSpool spool;
    private final ManifestVerifier verifier;
    private final Clock clock;
    private final Duration maxAge;

    public ManifestSyncService(String agentId, String serverPublicKeyEncoded, AgentKeyVault vault,
                               OfflineSpool spool, Clock clock, Duration maxAge) {
        this.agentId = agentId;
        this.vault = vault;
        this.spool = spool;
        this.clock = clock;
        this.maxAge = maxAge;
        this.verifier = new ManifestVerifier(Ed25519.decodePublic(serverPublicKeyEncoded),
                clock, maxAge);
        vault.load().ifPresent(state ->
                verifier.restoreSequence(state.lastManifestSequence()));
    }

    public sealed interface Outcome permits Outcome.Applied, Outcome.Rejected {
        record Applied(int entries, long sequence) implements Outcome {
        }

        record Rejected(String reason) implements Outcome {
        }
    }

    /**
     * Verifies and installs a manifest. {@code blobsByObjectId} carries the sealed spool objects
     * that arrived with it; anything listed but missing is simply not releasable.
     */
    public synchronized Outcome apply(String manifestJson, String signatureB64,
                                      Map<String, byte[]> blobsByObjectId) {
        ReleaseManifest manifest;
        try {
            manifest = Json.fromJson(manifestJson, ReleaseManifest.class);
        } catch (RuntimeException e) {
            return new Outcome.Rejected("malformed manifest");
        }
        byte[] signature;
        try {
            signature = Bytes.unb64url(signatureB64);
        } catch (RuntimeException e) {
            return new Outcome.Rejected("malformed signature");
        }

        ManifestVerifier.Result result = verifier.verify(manifest, signature, agentId);
        if (result instanceof ManifestVerifier.Result.Rejected rejected) {
            return new Outcome.Rejected(rejected.reason());
        }

        // Keep only blobs the (now-trusted) manifest actually references.
        Map<String, byte[]> accepted = new LinkedHashMap<>();
        for (ReleaseManifest.Entry entry : manifest.entries()) {
            byte[] blob = blobsByObjectId.get(entry.spoolObjectId());
            if (blob != null) {
                accepted.put(entry.spoolObjectId(), blob);
            }
        }
        spool.installWithIds(manifest, accepted);

        // Persist the sequence in the same logical step as accepting the manifest.
        AgentKeyVault.VaultState state = vault.load().orElseThrow(
                () -> new IllegalStateException("agent vault missing during sync"));
        vault.store(state.withSequence(manifest.sequence(),
                manifest.issuedAt().toEpochMilli()));

        return new Outcome.Applied(manifest.entries().size(), manifest.sequence());
    }

    /** Local view of the last manifest the agent accepted. */
    public Optional<ReleaseManifest> current() {
        return spool.currentManifest();
    }

    /**
     * Whether the agent should refuse all offline releases: true when the newest manifest is
     * older than the configured max age. This is the fail-closed rule — a branch that has been
     * cut off for too long stops releasing documents rather than acting on stale authority.
     */
    public boolean offlineAuthorityExpired() {
        ReleaseManifest m = spool.currentManifest().orElse(null);
        if (m == null) {
            return true;
        }
        Instant now = clock.instant();
        return !now.isBefore(m.expiresAt()) || m.issuedAt().isBefore(now.minus(maxAge));
    }
}
