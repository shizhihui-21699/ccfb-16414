package com.secureprint.core.crypto;

import com.secureprint.core.util.Bytes;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Ed25519 signatures for release grants and agent assertions.
 *
 * <p>Ed25519 is chosen over RSA/ECDSA for its small keys, deterministic signatures (no nonce
 * reuse risk) and because Java 15+ provides it in the default provider with no extra dependency.
 */
public final class Ed25519 {

    public static final String ALG = "Ed25519";

    private Ed25519() {
    }

    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance(ALG).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 keygen unavailable", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance(ALG);
            s.initSign(key);
            s.update(message);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 sign failed", e);
        }
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        try {
            Signature s = Signature.getInstance(ALG);
            s.initVerify(key);
            s.update(message);
            return s.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
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
            return KeyFactory.getInstance(ALG)
                    .generatePublic(new X509EncodedKeySpec(Bytes.unb64url(encoded)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("bad Ed25519 public key", e);
        }
    }

    public static PrivateKey decodePrivate(String encoded) {
        try {
            return KeyFactory.getInstance(ALG)
                    .generatePrivate(new PKCS8EncodedKeySpec(Bytes.unb64url(encoded)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("bad Ed25519 private key", e);
        }
    }
}
