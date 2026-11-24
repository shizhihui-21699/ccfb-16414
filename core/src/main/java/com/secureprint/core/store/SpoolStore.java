package com.secureprint.core.store;

import java.util.Optional;

/**
 * Abstract blob store for sealed spool objects. The server keeps these on the same hardened
 * volume it uses for backups; branch agents keep them on local disk so a release can happen
 * with the WAN down.
 */
public interface SpoolStore {

    void put(String objectId, byte[] sealedBytes);

    Optional<byte[]> get(String objectId);

    /** Idempotent: deleting a missing object is not an error. */
    void delete(String objectId);

    boolean exists(String objectId);
}
