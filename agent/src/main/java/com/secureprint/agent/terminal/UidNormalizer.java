package com.secureprint.agent.terminal;

import java.util.Locale;
import java.util.Optional;

/**
 * Normalises the many UID formats real readers emit into one canonical hex form.
 *
 * <p>This is quiet, unglamorous code that decides whether the whole system works. The same badge
 * tapped at a Shanghai reader (decimal, 10 digits, trailing CR) and a Munich reader (8 hex digits,
 * lowercase, terminated by Enter) must hash to the same digest, or employees "fail to authenticate
 * at some printers". The canonical form is: uppercase hex, no separators, big-endian byte order.
 *
 * <p>Explicitly supported:
 * <ul>
 *   <li>hex, with or without {@code 0x}, {@code :} or {@code -} separators</li>
 *   <li>decimal digits (Wiegand 26/35 readers commonly emit this)</li>
 *   <li>trailing CR/LF/tab from keyboard-wedge readers</li>
 *   <li>lowercase hex</li>
 * </ul>
 *
 * <p>Anything else is rejected rather than guessed, so a misconfigured reader fails loudly at
 * enrollment testing instead of intermittently.
 */
public final class UidNormalizer {

    private UidNormalizer() {
    }

    public static Optional<String> canonicalize(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String s = raw.replaceAll("[\\r\\n\\t\\u0000]", "").trim();
        if (s.isEmpty()) {
            return Optional.empty();
        }
        if (s.regionMatches(true, 0, "0x", 0, 2)) {
            s = s.substring(2);
        }
        String stripped = s.replace(":", "").replace("-", "").replace(" ", "");
        if (stripped.isEmpty()) {
            return Optional.empty();
        }
        if (stripped.matches("[0-9A-Fa-f]+")) {
            // Ambiguous: all-digits could be decimal. Readers that emit hex are the norm for
            // 8/16/20-digit UIDs; treat pure digits as decimal only when length is not a
            // plausible hex UID length (8, 16, 20, 24).
            if (stripped.matches("[0-9]+") && !isPlausibleHexLength(stripped.length())) {
                return decimalToHex(stripped);
            }
            return Optional.of(stripped.toUpperCase(Locale.ROOT));
        }
        return Optional.empty();
    }

    private static boolean isPlausibleHexLength(int len) {
        return len == 8 || len == 16 || len == 20 || len == 24 || len == 32;
    }

    private static Optional<String> decimalToHex(String digits) {
        try {
            java.math.BigInteger value = new java.math.BigInteger(digits, 10);
            String hex = value.toString(16).toUpperCase(Locale.ROOT);
            if ((hex.length() & 1) != 0) {
                hex = "0" + hex;
            }
            return Optional.of(hex);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}
