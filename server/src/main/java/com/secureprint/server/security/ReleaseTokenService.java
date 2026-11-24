package com.secureprint.server.security;

import com.secureprint.core.crypto.Hkdf;
import com.secureprint.core.util.Bytes;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Mints and verifies the one-time release tokens carried by each held job.
 *
 * <p>Flow: on submission the employee's client receives a token (a random 32-byte secret). The
 * server stores only its HMAC hash on the job. At release the client presents the token, and the
 * server compares hashes in constant time. Tokens are single-use: claiming a job consumes it.
 *
 * <p>Why a token at all, given the badge? Because the badge proves <em>who is standing at the
 * printer</em>, while the token proves <em>this job belongs to that person's submission</em> and
 * was not injected into their queue by someone who knows their employee id. Token plus badge
 * plus server-side ownership check gives defence in depth without extra user steps: the client
 * holds the token, and the terminal silently includes it when the employee picks the job.
 */
public final class ReleaseTokenService {

    private final byte[] tokenKey;

    public ReleaseTokenService(byte[] masterSecret) {
        this.tokenKey = Hkdf.derive(masterSecret, null, "release-token/v1", 32);
    }

    public record Issued(String token, String tokenHash) {
    }

    public Issued issue() {
        byte[] raw = Bytes.random(32);
        String token = Bytes.b64url(raw);
        return new Issued(token, hash(token));
    }

    public String hash(String token) {
        String normalised = token == null ? "" : token.trim();
        return com.secureprint.core.crypto.Hmac.macHex(tokenKey, "token|" + normalised);
    }

    /** Constant-time comparison of a presented token against the stored hash. */
    public boolean verify(String presentedToken, String storedHash) {
        if (presentedToken == null || storedHash == null) {
            return false;
        }
        byte[] presented = Bytes.unhex(hash(presentedToken));
        byte[] stored;
        try {
            stored = Bytes.unhex(storedHash);
        } catch (IllegalArgumentException e) {
            return false;
        }
        return Bytes.constantTimeEquals(presented, stored);
    }
}
