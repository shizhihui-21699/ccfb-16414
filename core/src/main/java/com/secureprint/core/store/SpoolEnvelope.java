package com.secureprint.core.store;

import com.secureprint.core.crypto.AesGcm;
import com.secureprint.core.crypto.CryptoException;
import com.secureprint.core.crypto.Hkdf;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.core.util.Bytes;
import com.secureprint.core.util.Json;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Envelope encryption for held jobs.
 *
 * <p>Two layers, deliberately:
 * <ol>
 *   <li>Each job gets a fresh random 256-bit <b>data key</b>. Document bytes plus the
 *       {@link PrintSpec} are sealed under it with AES-GCM.</li>
 *   <li>The data key is itself sealed under a <b>key-encryption key</b> (KEK) derived from the
 *       installation master secret via HKDF. Only the wrapped key is stored next to the job.</li>
 * </ol>
 *
 * <p>This means: destroying a job is a single key-wrap deletion (crypto-shredding) that makes
 * the ciphertext permanently unrecoverable even if a backup of the blob survives; and rotating
 * the KEK only requires re-wrapping data keys, never re-encrypting documents.
 *
 * <p>The AAD binds the envelope to the job id and owner, so a sealed payload cannot be moved
 * to a different job record by anyone with write access to the metadata store.
 */
public final class SpoolEnvelope {

    private static final byte FORMAT = 2;

    private final byte[] kek;

    public SpoolEnvelope(byte[] masterSecret) {
        if (masterSecret == null || masterSecret.length < 32) {
            throw new IllegalArgumentException("master secret must be >= 32 bytes");
        }
        this.kek = Hkdf.derive(masterSecret, Bytes.utf8("secure-print/spool"),
                "spool-kek/v2", 32);
    }

    public record Sealed(byte[] wrappedKey, byte[] ciphertext) {
    }

    public Sealed seal(String jobId, String ownerEmployeeId, byte[] documentBytes, PrintSpec spec) {
        byte[] dataKey = Bytes.random(32);
        try {
            byte[] aad = contentAad(jobId, ownerEmployeeId);
            byte[] specBytes = Json.toCanonicalBytes(spec);
            ByteBuffer plain = ByteBuffer.allocate(4 + specBytes.length + documentBytes.length);
            plain.putInt(specBytes.length).put(specBytes).put(documentBytes);

            byte[] ciphertext = AesGcm.seal(dataKey, plain.array(), aad);
            byte[] wrappedKey = AesGcm.seal(kek, dataKey, keyAad(jobId, ownerEmployeeId));
            return new Sealed(wrappedKey, ciphertext);
        } finally {
            java.util.Arrays.fill(dataKey, (byte) 0);
        }
    }

    public record Opened(PrintSpec spec, byte[] documentBytes) {
    }

    public Opened open(String jobId, String ownerEmployeeId, byte[] wrappedKey, byte[] ciphertext) {
        byte[] dataKey = AesGcm.open(kek, wrappedKey, keyAad(jobId, ownerEmployeeId));
        try {
            byte[] plain = AesGcm.open(dataKey, ciphertext, contentAad(jobId, ownerEmployeeId));
            ByteBuffer buf = ByteBuffer.wrap(plain);
            int specLen = buf.getInt();
            if (specLen <= 0 || specLen > plain.length - 4) {
                throw new CryptoException("corrupt envelope header");
            }
            byte[] specBytes = new byte[specLen];
            buf.get(specBytes);
            byte[] doc = new byte[buf.remaining()];
            buf.get(doc);
            return new Opened(Json.fromBytes(specBytes, PrintSpec.class), doc);
        } finally {
            java.util.Arrays.fill(dataKey, (byte) 0);
        }
    }

    /** Crypto-shred: discard the wrapped key. The ciphertext is inert from that instant. */
    public static byte[] shred() {
        return new byte[0];
    }

    /**
     * Recovers the job's data key from its KEK-wrapped form, for the sole purpose of re-wrapping
     * it to a branch agent. The caller must zero the returned array when done.
     */
    public byte[] unwrapDataKey(String jobId, String ownerEmployeeId, byte[] wrappedKey) {
        return AesGcm.open(kek, wrappedKey, keyAad(jobId, ownerEmployeeId));
    }

    /**
     * Opens a sealed payload given the raw data key directly — the agent-side path. The agent
     * never has the KEK; it receives {@code dataKey} only inside an ECIES blob addressed to it
     * and bound to the job and agent ids.
     */
    public static Opened openWithDataKey(byte[] dataKey, String jobId, String ownerEmployeeId,
                                         byte[] ciphertext) {
        byte[] plain = AesGcm.open(dataKey, ciphertext, contentAad(jobId, ownerEmployeeId));
        ByteBuffer buf = ByteBuffer.wrap(plain);
        int specLen = buf.getInt();
        if (specLen <= 0 || specLen > plain.length - 4) {
            throw new CryptoException("corrupt envelope header");
        }
        byte[] specBytes = new byte[specLen];
        buf.get(specBytes);
        byte[] doc = new byte[buf.remaining()];
        buf.get(doc);
        return new Opened(Json.fromBytes(specBytes, PrintSpec.class), doc);
    }

    /** AAD used when a job's data key is re-wrapped to a specific agent. */
    public static byte[] agentKeyAad(String agentId, String jobId, String ownerEmployeeId) {
        return Bytes.utf8("agent-data-key|" + FORMAT + "|" + agentId + "|" + jobId + "|"
                + ownerEmployeeId);
    }

    private static byte[] contentAad(String jobId, String owner) {
        return Bytes.utf8("spool-content|" + FORMAT + "|" + jobId + "|" + owner);
    }

    private static byte[] keyAad(String jobId, String owner) {
        return Bytes.utf8("spool-key|" + FORMAT + "|" + jobId + "|" + owner);
    }

    /** Envelope byte layout as persisted: [format][u16 wrappedKeyLen][wrappedKey][ciphertext]. */
    public static byte[] pack(Sealed sealed) {
        Objects.requireNonNull(sealed.ciphertext());
        if (sealed.wrappedKey().length > 0xFFFF) {
            throw new IllegalStateException("wrapped key too long");
        }
        ByteBuffer b = ByteBuffer.allocate(3 + sealed.wrappedKey().length + sealed.ciphertext().length);
        b.put(FORMAT);
        b.putShort((short) sealed.wrappedKey().length);
        b.put(sealed.wrappedKey()).put(sealed.ciphertext());
        return b.array();
    }

    public static Sealed unpack(byte[] packed) {
        ByteBuffer b = ByteBuffer.wrap(packed);
        byte format = b.get();
        if (format != FORMAT) {
            throw new CryptoException("unsupported spool format " + format);
        }
        int keyLen = b.getShort() & 0xFFFF;
        if (keyLen <= 0 || keyLen > b.remaining()) {
            throw new CryptoException("corrupt spool envelope");
        }
        byte[] wk = new byte[keyLen];
        b.get(wk);
        byte[] ct = new byte[b.remaining()];
        b.get(ct);
        return new Sealed(wk, ct);
    }

}
