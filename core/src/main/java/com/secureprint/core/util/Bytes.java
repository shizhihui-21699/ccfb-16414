package com.secureprint.core.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;

/** Encoding helpers and constant-time comparisons. */
public final class Bytes {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Bytes() {
    }

    public static byte[] random(int n) {
        byte[] out = new byte[n];
        RNG.nextBytes(out);
        return out;
    }

    public static SecureRandom rng() {
        return RNG;
    }

    public static String hex(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    public static byte[] unhex(String s) {
        String v = s.toLowerCase(Locale.ROOT);
        if ((v.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[v.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(v.charAt(i * 2), 16);
            int lo = Character.digit(v.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("bad hex digit");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String b64url(byte[] data) {
        return B64URL.encodeToString(data);
    }

    public static byte[] unb64url(String s) {
        return B64URL_DEC.decode(s);
    }

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    public static String sha256Hex(byte[] data) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Length-safe, non-short-circuiting comparison. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }

}
