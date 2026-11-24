package com.secureprint.core.crypto;

import com.secureprint.core.util.Bytes;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/**
 * ECIES over X25519 + HKDF + AES-256-GCM.
 *
 * <p>Used to wrap a job's one-time data key to a specific recipient (a branch release agent).
 * The sender needs only the recipient's public key, so an agent can be provisioned offline and
 * its private key never leaves its site's keystore. This is what makes <em>release while the WAN
 * is down</em> possible: the server pre-wraps keys to every agent that might need them.
 *
 * <p>Wire format: {@code [1 version][44 ephemeral SPKI][12 IV][ciphertext||tag]}.
 */
public final class Ecies {

    private static final byte VERSION = 1;
    private static final int SPKI_LEN = 44;
    private static final int MIN_LEN = 1 + SPKI_LEN + AesGcm.IV_BYTES + 16;

    private Ecies() {
    }

    public static KeyPair generateRecipientKeyPair() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("X25519 unavailable in this JDK", e);
        }
    }

    public static String encodePublic(PublicKey key) {
        return Bytes.b64url(key.getEncoded());
    }

    public static String encodePrivate(PrivateKey key) {
        return Bytes.b64url(key.getEncoded());
    }

    public static PublicKey decodePublic(String encoded) {
        try {
            return KeyFactory.getInstance("X25519")
                    .generatePublic(new X509EncodedKeySpec(Bytes.unb64url(encoded)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("bad X25519 public key", e);
        }
    }

    public static PrivateKey decodePrivate(String encoded) {
        try {
            return KeyFactory.getInstance("X25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(Bytes.unb64url(encoded)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("bad X25519 private key", e);
        }
    }

    public static byte[] seal(PublicKey recipient, byte[] plaintext, byte[] aad) {
        KeyPair ephemeral = generateRecipientKeyPair();
        byte[] shared = agreement(ephemeral.getPrivate(), recipient);
        byte[] key = deriveKey(shared, ephemeral.getPublic(), recipient);
        try {
            byte[] sealed = AesGcm.seal(key, plaintext, aad);
            byte[] spki = ephemeral.getPublic().getEncoded();
            ByteBuffer out = ByteBuffer.allocate(VERSION_SIZE + spki.length + sealed.length);
            out.put(VERSION).put(spki).put(sealed);
            return out.array();
        } finally {
            Arrays.fill(shared, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Opens a blob sealed to {@code recipient}.
     *
     * <p>{@code ownPublic} must be the public half of {@code recipient}: the key derivation salt
     * binds both parties' public keys, so the recipient cannot recover it from the private key
     * alone and must supply it. The helper {@link #recipientKeys()} keeps the pair together.
     */
    public static byte[] open(PrivateKey recipient, PublicKey ownPublic, byte[] blob, byte[] aad) {
        if (blob == null || blob.length < MIN_LEN) {
            throw new CryptoException("sealed blob too short");
        }
        ByteBuffer in = ByteBuffer.wrap(blob);
        byte version = in.get();
        if (version != VERSION) {
            throw new CryptoException("unsupported ECIES version " + version);
        }
        byte[] spki = new byte[SPKI_LEN];
        in.get(spki);
        PublicKey ephemeralPub;
        try {
            ephemeralPub = KeyFactory.getInstance("X25519")
                    .generatePublic(new X509EncodedKeySpec(spki));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("bad ephemeral key", e);
        }
        byte[] shared = agreement(recipient, ephemeralPub);
        byte[] key = deriveKey(shared, ephemeralPub, ownPublic);
        try {
            byte[] body = new byte[in.remaining()];
            in.get(body);
            return AesGcm.open(key, body, aad);
        } finally {
            Arrays.fill(shared, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
    }

    /** A recipient key pair plus its encodings, so callers never lose the public half. */
    public record RecipientKeys(String publicEncoded, String privateEncoded) {

        public PublicKey publicKey() {
            return decodePublic(publicEncoded);
        }

        public PrivateKey privateKey() {
            return decodePrivate(privateEncoded);
        }

        public String fingerprint() {
            return Ecies.fingerprint(publicKey());
        }

        /**
         * Opens a blob addressed to this key pair. Preferred over the static {@code open} because
         * it cannot be called with a public key that does not belong to the private key — the
         * static form would derive a different wrapping key and fail confusingly.
         */
        public byte[] open(byte[] blob, byte[] aad) {
            return Ecies.open(privateKey(), publicKey(), blob, aad);
        }

        public byte[] open(String blobB64Url, byte[] aad) {
            return open(Bytes.unb64url(blobB64Url), aad);
        }
    }

    public static RecipientKeys recipientKeys() {
        KeyPair kp = generateRecipientKeyPair();
        return new RecipientKeys(encodePublic(kp.getPublic()), encodePrivate(kp.getPrivate()));
    }

    /** Short, human-checkable fingerprint for provisioning manifests and logs. */
    public static String fingerprint(PublicKey key) {
        return Bytes.hex(Hkdf.derive(key.getEncoded(), null, "ecies-fingerprint/v1", 8));
    }

    private static final int VERSION_SIZE = 1;

    private static byte[] deriveKey(byte[] shared, PublicKey ephemeralPub, PublicKey recipientPub) {
        byte[] salt = Hkdf.concat(ephemeralPub.getEncoded(), recipientPub.getEncoded());
        return Hkdf.derive(shared, salt, "ecies/x25519/aes256gcm/v1", 32);
    }

    private static byte[] agreement(PrivateKey priv, PublicKey pub) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(priv);
            ka.doPhase(pub, true);
            return ka.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("X25519 agreement failed", e);
        }
    }
}
