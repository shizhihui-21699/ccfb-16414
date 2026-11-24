package com.secureprint.agent.store;

import com.secureprint.core.protocol.ReleaseManifest;
import com.secureprint.core.store.SpoolEnvelope;
import com.secureprint.core.store.SpoolStore;
import com.secureprint.core.crypto.Ecies;
import com.secureprint.core.util.Bytes;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The agent's offline working set: the last verified manifest plus the sealed spool blobs it
 * references, kept on local disk.
 *
 * <p>Two things make offline release possible here and nowhere else:
 * <ol>
 *   <li>The manifest lists jobs <em>and</em> each job's data key wrapped to this agent's public
 *       key, so the agent can decrypt without the server.</li>
 *   <li>The sealed blobs are the ciphertexts the server pushed; deleting one locally (or when it
 *       falls out of a later manifest) is as final as deleting it on the server.</li>
 * </ol>
 *
 * <p>Retention rule enforced on each sync: <b>anything not in the new manifest is destroyed
 * locally</b>. That is how a cancel, an expiry or a release elsewhere propagates to an offline
 * branch the moment it reconnects — and it is why manifests must be fresh (short TTL) for the
 * window the branch is allowed to act alone.
 */
public final class OfflineSpool {

    private final SpoolStore store;
    private final Clock clock;
    private volatile ReleaseManifest manifest;
    private final Map<String, String> wrappedKeys = new ConcurrentHashMap<>();

    public OfflineSpool(SpoolStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    /**
     * Installs a freshly verified manifest and its blobs, then destroys everything the new
     * manifest no longer lists. Callers must have verified the manifest signature and sequence
     * before calling this.
     */
    public synchronized void install(ReleaseManifest newManifest, List<byte[]> packedBlobs) {
        if (manifest != null && newManifest.sequence() <= manifest.sequence()) {
            throw new IllegalArgumentException("manifest sequence must increase: have "
                    + manifest.sequence() + " got " + newManifest.sequence());
        }
        Map<String, String> newKeys = new ConcurrentHashMap<>();
        for (ReleaseManifest.Entry entry : newManifest.entries()) {
            newKeys.put(entry.jobId(), entry.jobDataKeyWrapped());
        }
        java.util.Set<String> liveObjects = new java.util.HashSet<>();
        for (ReleaseManifest.Entry entry : newManifest.entries()) {
            liveObjects.add(entry.spoolObjectId());
        }
        for (String prior : wrappedKeys.keySet()) {
            if (!newKeys.containsKey(prior)) {
                // Job vanished from the manifest: cancelled, expired, or released elsewhere.
                manifestEntry(prior).ifPresent(e -> store.delete(e.spoolObjectId()));
            }
        }
        // Persist blobs (idempotent on the store side).
        List<ReleaseManifest.Entry> entries = newManifest.entries();
        for (int i = 0; i < Math.min(packedBlobs.size(), entries.size()); i++) {
            store.put(entries.get(i).spoolObjectId(), packedBlobs.get(i));
        }
        this.wrappedKeys.clear();
        this.wrappedKeys.putAll(newKeys);
        this.manifest = newManifest;
    }

    /** Convenience for the sync service: keeps manifest and blob objects aligned by id. */
    public synchronized void installWithIds(ReleaseManifest newManifest,
                                            Map<String, byte[]> blobsByObjectId) {
        if (manifest != null && newManifest.sequence() <= manifest.sequence()) {
            throw new IllegalArgumentException("manifest sequence must increase");
        }
        java.util.Set<String> newJobIds = new java.util.HashSet<>();
        for (ReleaseManifest.Entry e : newManifest.entries()) {
            newJobIds.add(e.jobId());
        }
        // Destroy local blobs for jobs that vanished from the manifest. Look the entry up in the
        // OLD manifest, because the new one no longer describes them.
        for (String prior : new ArrayList<>(wrappedKeys.keySet())) {
            if (!newJobIds.contains(prior)) {
                manifestEntry(prior).ifPresent(e -> store.delete(e.spoolObjectId()));
            }
        }
        blobsByObjectId.forEach(store::put);
        Map<String, String> nextKeys = new ConcurrentHashMap<>();
        for (ReleaseManifest.Entry e : newManifest.entries()) {
            nextKeys.put(e.jobId(), e.jobDataKeyWrapped());
        }
        wrappedKeys.clear();
        wrappedKeys.putAll(nextKeys);
        this.manifest = newManifest;
    }

    private Optional<ReleaseManifest.Entry> manifestEntry(String jobId) {
        ReleaseManifest m = manifest;
        return m == null ? Optional.empty() : Optional.ofNullable(m.entry(jobId));
    }

    public Optional<ReleaseManifest> currentManifest() {
        return Optional.ofNullable(manifest);
    }

    /** Jobs this agent could release for the employee right now, per the local manifest. */
    public List<ReleaseManifest.Entry> releasableFor(String employeeId) {
        ReleaseManifest m = manifest;
        if (m == null) {
            return List.of();
        }
        Instant now = clock.instant();
        if (!m.isUsableAt(now)) {
            return List.of();
        }
        List<ReleaseManifest.Entry> out = new ArrayList<>();
        for (ReleaseManifest.Entry e : m.entriesFor(employeeId)) {
            if (now.isBefore(e.holdUntil())) {
                out.add(e);
            }
        }
        return out;
    }

    /**
     * Decrypts a job from local state using the data key the server wrapped to this agent.
     *
     * @param agentPrivate the agent's X25519 private key
     * @param agentPublic  its public half (needed for the ECIES salt)
     */
    public Optional<SpoolEnvelope.Opened> open(String jobId, String employeeId,
                                               java.security.PrivateKey agentPrivate,
                                               java.security.PublicKey agentPublic) {
        ReleaseManifest m = manifest;
        if (m == null) {
            return Optional.empty();
        }
        ReleaseManifest.Entry entry = m.entry(jobId);
        if (entry == null || !entry.employeeId().equals(employeeId)) {
            return Optional.empty();
        }
        if (!clock.instant().isBefore(entry.holdUntil())) {
            return Optional.empty();
        }
        String wrapped = wrappedKeys.get(jobId);
        if (wrapped == null) {
            return Optional.empty();
        }
        byte[] packed = store.get(entry.spoolObjectId()).orElse(null);
        if (packed == null) {
            return Optional.empty();
        }
        byte[] dataKey = Ecies.open(agentPrivate, agentPublic, Bytes.unb64url(wrapped),
                SpoolEnvelope.agentKeyAad(m.agentId(), jobId, employeeId));
        try {
            SpoolEnvelope.Sealed sealed = SpoolEnvelope.unpack(packed);
            return Optional.of(SpoolEnvelope.openWithDataKey(dataKey, jobId, employeeId,
                    sealed.ciphertext()));
        } finally {
            java.util.Arrays.fill(dataKey, (byte) 0);
        }
    }

    /** Raw sealed spool bytes for a job, if present locally. */
    public Optional<byte[]> rawSpoolFor(String jobId) {
        ReleaseManifest m = manifest;
        if (m == null) {
            return Optional.empty();
        }
        ReleaseManifest.Entry entry = m.entry(jobId);
        if (entry == null) {
            return Optional.empty();
        }
        return store.get(entry.spoolObjectId());
    }

    /** Called after a successful local release: the job must not print again from this agent. */
    public synchronized void touchReleased(String jobId) {
        manifestEntry(jobId).ifPresent(e -> store.delete(e.spoolObjectId()));
        wrappedKeys.remove(jobId);
    }

    public int entries() {
        return wrappedKeys.size();
    }

}
