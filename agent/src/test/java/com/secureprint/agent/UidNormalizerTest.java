package com.secureprint.agent;

import com.secureprint.agent.terminal.UidNormalizer;
import com.secureprint.core.crypto.Hmac;
import com.secureprint.core.util.Bytes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The same badge must produce the same digest no matter which reader format it arrived in.
 * This is the difference between "works in Shanghai" and "works everywhere".
 */
class UidNormalizerTest {

    @Test
    void hexWithSeparatorsNormalisesToOneForm() {
        assertEquals("4A1B9C2D", UidNormalizer.canonicalize("4a:1b:9c:2d").orElseThrow());
        assertEquals("4A1B9C2D", UidNormalizer.canonicalize("4A-1B-9C-2D").orElseThrow());
        assertEquals("4A1B9C2D", UidNormalizer.canonicalize("0x4a1b9c2d").orElseThrow());
        assertEquals("4A1B9C2D", UidNormalizer.canonicalize(" 4A1B9C2D\r\n").orElseThrow());
    }

    @Test
    void decimalWiegandIsConvertedToHex() {
        // 10-digit decimal is not a plausible hex UID length -> treated as decimal.
        // 0x4A1B9C2D = 1243323437
        String out = UidNormalizer.canonicalize("1243323437").orElseThrow();
        assertEquals("4A1B9C2D", out);
    }

    @Test
    void eightDigitAllNumericStaysHexBecauseThatIsTheCommonReaderFormat() {
        assertEquals("12345678", UidNormalizer.canonicalize("12345678").orElseThrow());
    }

    @Test
    void readerFormatsConvergeToTheSameDigest() {
        byte[] pepper = Bytes.random(32);
        String a = Hmac.badgeDigest(pepper, UidNormalizer.canonicalize("4a:1b:9c:2d")
                .orElseThrow());
        String b = Hmac.badgeDigest(pepper, UidNormalizer.canonicalize("4A-1B-9C-2D")
                .orElseThrow());
        String c = Hmac.badgeDigest(pepper, UidNormalizer.canonicalize("1243323437")
                .orElseThrow());
        assertEquals(a, b);
        assertEquals(a, c, "decimal and hex readings of one badge must agree");
    }

    @Test
    void garbageIsRejected() {
        assertTrue(UidNormalizer.canonicalize("").isEmpty());
        assertTrue(UidNormalizer.canonicalize("  ").isEmpty());
        assertTrue(UidNormalizer.canonicalize("ZZZZ").isEmpty());
        assertTrue(UidNormalizer.canonicalize(null).isEmpty());
    }

    @Test
    void digestIsPepperDependentAndStable() {
        String uid = "4A1B9C2D";
        String a = Hmac.badgeDigest(Bytes.random(32), uid);
        String b = Hmac.badgeDigest(Bytes.random(32), uid);
        assertFalse(a.equals(b), "different peppers must give different digests");

        byte[] pepper = Bytes.random(32);
        assertEquals(Hmac.badgeDigest(pepper, uid), Hmac.badgeDigest(pepper, uid));
    }
}
