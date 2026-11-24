package com.secureprint.core.crypto;

/** Thrown when a cryptographic guarantee is violated: bad tag, bad key, malformed envelope. */
public class CryptoException extends RuntimeException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
