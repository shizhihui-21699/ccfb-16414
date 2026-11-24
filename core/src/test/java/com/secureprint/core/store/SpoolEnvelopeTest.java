package com.secureprint.core.store;

import com.secureprint.core.crypto.CryptoException;
import com.secureprint.core.domain.ColorMode;
import com.secureprint.core.domain.DuplexMode;
import com.secureprint.core.domain.PaperSize;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.core.util.Bytes;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SpoolEnvelopeTest {

    private static PrintSpec spec() {
        return new PrintSpec("Payslip-2026-11.pdf", "application/pdf", 2, ColorMode.MONO,
                DuplexMode.LONG_EDGE, PaperSize.A4, List.of(1, 2), false, "PAYROLL",
                Instant.parse("2026-11-25T09:00:00Z"));
    }

    @Test
    void roundTripPreservesDocumentAndSpec() {
        byte[] master = Bytes.random(32);
        SpoolEnvelope env = new SpoolEnvelope(master);
        byte[] doc = "confidential payroll bytes".getBytes();

        SpoolEnvelope.Sealed sealed = env.seal("job-1", "emp-1", doc, spec());
        byte[] packed = SpoolEnvelope.pack(sealed);
        SpoolEnvelope.Sealed unpacked = SpoolEnvelope.unpack(packed);
        SpoolEnvelope.Opened opened = env.open("job-1", "emp-1",
                unpacked.wrappedKey(), unpacked.ciphertext());

        assertArrayEquals(doc, opened.documentBytes());
        assertEquals("Payslip-2026-11.pdf", opened.spec().documentName());
        assertEquals(2, opened.spec().copies());
    }

    @Test
    void ciphertextDoesNotContainPlaintext() {
        SpoolEnvelope env = new SpoolEnvelope(Bytes.random(32));
        byte[] doc = Bytes.utf8("SALARY 12345678");
        SpoolEnvelope.Sealed sealed = env.seal("job-2", "emp-1", doc, spec());
        String ctAsText = new String(sealed.ciphertext(), java.nio.charset.StandardCharsets.ISO_8859_1);
        assertFalse(ctAsText.contains("SALARY"), "plaintext must not appear in ciphertext");
    }

    @Test
    void envelopeIsBoundToJobIdAndOwner() {
        SpoolEnvelope env = new SpoolEnvelope(Bytes.random(32));
        SpoolEnvelope.Sealed sealed = env.seal("job-3", "emp-1", Bytes.utf8("x"), spec());

        // Same key material, different job id -> AAD mismatch -> refusal.
        assertThrows(CryptoException.class,
                () -> env.open("job-4", "emp-1", sealed.wrappedKey(), sealed.ciphertext()));
        assertThrows(CryptoException.class,
                () -> env.open("job-3", "emp-2", sealed.wrappedKey(), sealed.ciphertext()));
    }

    @Test
    void tamperedCiphertextIsRejected() {
        SpoolEnvelope env = new SpoolEnvelope(Bytes.random(32));
        SpoolEnvelope.Sealed sealed = env.seal("job-5", "emp-1", Bytes.utf8("data"), spec());
        byte[] ct = sealed.ciphertext().clone();
        ct[ct.length / 2] ^= 0x01;
        assertThrows(CryptoException.class,
                () -> env.open("job-5", "emp-1", sealed.wrappedKey(), ct));
    }

    @Test
    void differentMasterSecretsCannotOpen() {
        SpoolEnvelope a = new SpoolEnvelope(Bytes.random(32));
        SpoolEnvelope b = new SpoolEnvelope(Bytes.random(32));
        SpoolEnvelope.Sealed sealed = a.seal("job-6", "emp-1", Bytes.utf8("data"), spec());
        assertThrows(CryptoException.class,
                () -> b.open("job-6", "emp-1", sealed.wrappedKey(), sealed.ciphertext()));
    }

    @Test
    void cryptoShredMakesBytesInert() {
        SpoolEnvelope env = new SpoolEnvelope(Bytes.random(32));
        SpoolEnvelope.Sealed sealed = env.seal("job-7", "emp-1", Bytes.utf8("data"), spec());
        byte[] shreddedKey = SpoolEnvelope.shred();
        assertThrows(CryptoException.class,
                () -> env.open("job-7", "emp-1", shreddedKey, sealed.ciphertext()));
    }

    @Test
    void emptyDocumentRoundTrips() {
        SpoolEnvelope env = new SpoolEnvelope(Bytes.random(32));
        SpoolEnvelope.Sealed sealed = env.seal("job-8", "emp-1", new byte[0], spec());
        SpoolEnvelope.Opened opened = env.open("job-8", "emp-1",
                sealed.wrappedKey(), sealed.ciphertext());
        assertTrue(opened.documentBytes().length == 0);
    }
}
