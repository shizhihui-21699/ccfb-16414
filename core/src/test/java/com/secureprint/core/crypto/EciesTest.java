package com.secureprint.core.crypto;

import com.secureprint.core.util.Bytes;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EciesTest {

    @Test
    void recipientCanOpenAndStrangerCannot() {
        Ecies.RecipientKeys recipient = Ecies.recipientKeys();
        Ecies.RecipientKeys stranger = Ecies.recipientKeys();
        byte[] secret = Bytes.random(32);
        byte[] aad = Bytes.utf8("grant-1");

        byte[] blob = Ecies.seal(recipient.publicKey(), secret, aad);
        assertArrayEquals(secret, Ecies.open(recipient.privateKey(), recipient.publicKey(),
                blob, aad));

        assertThrows(CryptoException.class, () -> Ecies.open(stranger.privateKey(),
                stranger.publicKey(), blob, aad));
    }

    @Test
    void aadMismatchFails() {
        Ecies.RecipientKeys r = Ecies.recipientKeys();
        byte[] blob = Ecies.seal(r.publicKey(), Bytes.random(32), Bytes.utf8("grant-1"));
        assertThrows(CryptoException.class, () -> Ecies.open(r.privateKey(), r.publicKey(),
                blob, Bytes.utf8("grant-2")));
    }

    @Test
    void eachSealUsesFreshEphemeralKey() {
        Ecies.RecipientKeys r = Ecies.recipientKeys();
        byte[] pt = Bytes.random(32);
        byte[] a = Ecies.seal(r.publicKey(), pt, new byte[0]);
        byte[] b = Ecies.seal(r.publicKey(), pt, new byte[0]);
        assertFalse(java.util.Arrays.equals(a, b), "ciphertexts must differ (fresh IV/ephemeral)");
    }

    @Test
    void keyEncodingsRoundTrip() {
        KeyPair kp = Ecies.generateRecipientKeyPair();
        String pub = Ecies.encodePublic(kp.getPublic());
        String priv = Ecies.encodePrivate(kp.getPrivate());
        assertArrayEquals(kp.getPublic().getEncoded(), Ecies.decodePublic(pub).getEncoded());
        assertArrayEquals(kp.getPrivate().getEncoded(), Ecies.decodePrivate(priv).getEncoded());
    }

    @Test
    void fingerprintIsStableAndDistinct() {
        Ecies.RecipientKeys a = Ecies.recipientKeys();
        Ecies.RecipientKeys b = Ecies.recipientKeys();
        assertNotEquals(a.fingerprint(), b.fingerprint());
        assertNotEquals(a.fingerprint(), a.publicEncoded());
    }
}
