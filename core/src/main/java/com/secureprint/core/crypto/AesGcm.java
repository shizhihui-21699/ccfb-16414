package com.secureprint.core.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * AES-256-GCM authenticated encryption.
 *
 * <p>Wire format: {@code [1 byte version][12 byte IV][ciphertext || 16 byte tag]}. The version
 * byte lets us rotate algorithms later without breaking already-sealed spool objects. The IV is
 * random per seal, never derived, because these keys see far more than 2^32 messages only in
 * theory — random 96-bit IVs are the safe choice for GCM at this volume.
 *
 * <p>Every call takes associated data (AAD). The spool passes job metadata as AAD so a sealed
 * blob cannot be transplanted onto another job id by someone who can write to the store.
 */
public final class AesGcm {

    public static final int KEY_BYTES = 32;
    public static final int IV_BYTES = 12;
    public static final int TAG_BITS = 128;
    private static final int TAG_BYTES = TAG_BITS / 8;
    private static final byte FORMAT_VERSION = 1;

    private AesGcm() {
    }

    public static byte[] seal(byte[] key, byte[] plaintext, byte[] aad) {
        requireKey(key);
        try {
            byte[] iv = com.secureprint.core.util.Bytes.random(IV_BYTES);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            byte[] ct = cipher.doFinal(plaintext);
            ByteBuffer out = ByteBuffer.allocate(1 + IV_BYTES + ct.length);
            out.put(FORMAT_VERSION).put(iv).put(ct);
            return out.array();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES-GCM seal failed", e);
        }
    }

    public static byte[] open(byte[] key, byte[] sealed, byte[] aad) {
        requireKey(key);
        if (sealed == null || sealed.length < 1 + IV_BYTES + TAG_BYTES) {
            throw new CryptoException("sealed blob too short");
        }
        ByteBuffer in = ByteBuffer.wrap(sealed);
        byte version = in.get();
        if (version != FORMAT_VERSION) {
            throw new CryptoException("unsupported envelope version " + version);
        }
        byte[] iv = new byte[IV_BYTES];
        in.get(iv);
        byte[] ct = new byte[in.remaining()];
        in.get(ct);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ct);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES-GCM open failed (tampered or wrong key)", e);
        }
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != KEY_BYTES) {
            throw new CryptoException("AES-256 key must be " + KEY_BYTES + " bytes");
        }
    }
}
