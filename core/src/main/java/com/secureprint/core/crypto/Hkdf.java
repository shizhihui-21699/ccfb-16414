package com.secureprint.core.crypto;

import com.secureprint.core.util.Bytes;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF-SHA256 (RFC 5869) used to derive purpose-separated subkeys from the master key.
 *
 * <p>Why bother instead of using the master key directly? Because spool encryption, token
 * signing and audit chaining must never share a key. If a token-signing oracle is ever found,
 * it must not be able to help an attacker decrypt spooled payroll PDFs.
 */
public final class Hkdf {

    private Hkdf() {
    }

    public static byte[] extract(byte[] salt, byte[] ikm) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt == null || salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
            return mac.doFinal(ikm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HKDF extract failed", e);
        }
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) {
        if (length <= 0 || length > 255 * 32) {
            throw new IllegalArgumentException("invalid HKDF output length " + length);
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] out = new byte[length];
            byte[] t = new byte[0];
            int pos = 0;
            for (int counter = 1; pos < length; counter++) {
                mac.reset();
                mac.update(t);
                mac.update(info == null ? new byte[0] : info);
                mac.update((byte) counter);
                t = mac.doFinal();
                int copy = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, out, pos, copy);
                pos += copy;
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HKDF expand failed", e);
        }
    }

    /** One-shot derive: HKDF(salt, ikm, info) → {@code length} bytes. */
    public static byte[] derive(byte[] ikm, byte[] salt, String info, int length) {
        byte[] prk = extract(salt, ikm);
        try {
            return expand(prk, Bytes.utf8(info), length);
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        ByteBuffer buf = ByteBuffer.allocate(a.length + b.length);
        buf.put(a).put(b);
        return buf.array();
    }
}
