package com.secureprint.core.crypto;

import com.secureprint.core.util.Bytes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/** HMAC-SHA256 primitives, used for badge hashing and token signing. */
public final class Hmac {

    private Hmac() {
    }

    public static byte[] mac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HMAC-SHA256 failed", e);
        }
    }

    public static byte[] mac(byte[] key, String data) {
        return mac(key, Bytes.utf8(data));
    }

    public static String macHex(byte[] key, String data) {
        return Bytes.hex(mac(key, data));
    }

    /**
     * Badge UIDs are never stored or transmitted raw; they exist only as this keyed digest.
     *
     * <p>Callers must pass an already-canonical UID (see the agent's {@code UidNormalizer}):
     * the same badge read as decimal at one reader and hex at another must produce one digest,
     * and normalisation is reader-format knowledge that belongs at the reader boundary, not
     * buried in a crypto primitive.
     */
    public static String badgeDigest(byte[] pepper, String canonicalBadgeUid) {
        if (canonicalBadgeUid == null || canonicalBadgeUid.isBlank()) {
            throw new IllegalArgumentException("badge UID required");
        }
        return macHex(pepper, "badge|" + canonicalBadgeUid);
    }
}
