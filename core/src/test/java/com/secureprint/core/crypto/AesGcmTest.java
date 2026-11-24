package com.secureprint.core.crypto;

import com.secureprint.core.util.Bytes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmTest {

    @Test
    void roundTripWithAad() {
        byte[] key = Bytes.random(32);
        byte[] pt = Bytes.utf8("hello sealed world");
        byte[] aad = Bytes.utf8("job-1");
        byte[] sealed = AesGcm.seal(key, pt, aad);
        assertArrayEquals(pt, AesGcm.open(key, sealed, aad));
    }

    @Test
    void wrongAadRejected() {
        byte[] key = Bytes.random(32);
        byte[] sealed = AesGcm.seal(key, Bytes.utf8("data"), Bytes.utf8("job-1"));
        assertThrows(CryptoException.class,
                () -> AesGcm.open(key, sealed, Bytes.utf8("job-2")));
    }

    @Test
    void ivIsRandomPerMessage() {
        byte[] key = Bytes.random(32);
        byte[] a = AesGcm.seal(key, Bytes.utf8("same"), new byte[0]);
        byte[] b = AesGcm.seal(key, Bytes.utf8("same"), new byte[0]);
        assertEquals(a.length, b.length);
        byte[] ivA = java.util.Arrays.copyOfRange(a, 1, 13);
        byte[] ivB = java.util.Arrays.copyOfRange(b, 1, 13);
        org.junit.jupiter.api.Assertions.assertFalse(java.util.Arrays.equals(ivA, ivB),
                "IVs must differ between messages");
    }

    @Test
    void rejectsWrongKeyLength() {
        assertThrows(CryptoException.class, () -> AesGcm.seal(new byte[16], new byte[1], null));
    }

    @Test
    void truncationRejected() {
        byte[] key = Bytes.random(32);
        byte[] sealed = AesGcm.seal(key, Bytes.utf8("data"), null);
        byte[] cut = java.util.Arrays.copyOf(sealed, sealed.length - 1);
        assertThrows(CryptoException.class, () -> AesGcm.open(key, cut, null));
    }
}
