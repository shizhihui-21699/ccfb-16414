package com.secureprint.drivers.format;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RleTest {

    @Test
    void roundTripsRandomRows() {
        Random r = new Random(42);
        for (int trial = 0; trial < 200; trial++) {
            int len = 1 + r.nextInt(400);
            byte[] row = new byte[len];
            r.nextBytes(row);
            byte[] encoded = Rle.encodeRow(row);
            assertArrayEquals(row, Rle.decodeRow(encoded, len));
        }
    }

    @Test
    void compressesLongRuns() {
        byte[] row = new byte[1000];
        java.util.Arrays.fill(row, (byte) 0xFF);
        byte[] encoded = Rle.encodeRow(row);
        assertTrue(encoded.length <= 16, "long run should compress to a few bytes, got "
                + encoded.length);
        assertArrayEquals(row, Rle.decodeRow(encoded, row.length));
    }

    @Test
    void handlesAlternatingBytes() {
        byte[] row = new byte[256];
        for (int i = 0; i < row.length; i++) {
            row[i] = (byte) (i % 2 == 0 ? 0x00 : 0xFF);
        }
        byte[] encoded = Rle.encodeRow(row);
        assertArrayEquals(row, Rle.decodeRow(encoded, row.length));
        assertTrue(encoded.length > row.length / 2, "alternating bytes cannot compress");
    }

    @Test
    void allWhiteRowCompressesWell() {
        byte[] row = new byte[600]; // 600 bytes of 0x00 = white
        byte[] encoded = Rle.encodeRow(row);
        // 4 full 128-byte runs + one 88-byte run = 5 runs, 2 bytes each.
        assertEquals(10, encoded.length);
        assertArrayEquals(row, Rle.decodeRow(encoded, row.length));
    }

    @Test
    void rejectsTruncatedInput() {
        assertThrows(IllegalArgumentException.class,
                () -> Rle.decodeRow(new byte[]{(byte) 250}, 100));
    }

    @Test
    void rejectsOverflow() {
        // one literal of 10 bytes claiming output of 10 into expected length 5
        byte[] enc = new byte[]{9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        assertThrows(IllegalArgumentException.class, () -> Rle.decodeRow(enc, 5));
    }

    @Test
    void emptyRowRoundTrips() {
        byte[] encoded = Rle.encodeRow(new byte[0]);
        assertEquals(0, encoded.length);
        assertArrayEquals(new byte[0], Rle.decodeRow(encoded, 0));
    }
}
