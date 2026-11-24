package com.secureprint.drivers.format;

import java.io.ByteArrayOutputStream;

/**
 * TIFF/PackBits RLE codec, the compression PCL5 raster mode 2 and PostScript
 * {@code RunLengthEncode} both use.
 *
 * <p>PackBits is trivially small to implement, which is why it is the default in printer
 * protocols: no dictionary table to ship, no decompressor state. Encoding rule:
 * <ul>
 *   <li>runs of 2..128 identical bytes → {@code [257-n][byte]}</li>
 *   <li>literal spans of 1..128 bytes → {@code [n-1][bytes...]}</li>
 *   <li>literal spans must be flushed before a run of 3+ starts, or the run is absorbed</li>
 * </ul>
 *
 * <p>Both {@link PclEncoder} and the PostScript encoder share this so a bug in one is a bug in
 * both, caught by the same round-trip test.
 */
public final class Rle {

    private Rle() {
    }

    public static byte[] encodeRow(byte[] row) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(row.length / 2 + 16);
        int i = 0;
        int n = row.length;
        while (i < n) {
            int runLen = 1;
            while (i + runLen < n && row[i + runLen] == row[i] && runLen < 128) {
                runLen++;
            }
            if (runLen >= 2) {
                out.write(257 - runLen);
                out.write(row[i] & 0xFF);
                i += runLen;
            } else {
                // Collect a literal span until the next run of >= 2 begins.
                int start = i;
                i++;
                while (i < n && i - start < 128) {
                    int look = 1;
                    while (i + look < n && row[i + look] == row[i] && look < 2) {
                        look++;
                    }
                    if (look >= 2) {
                        break;
                    }
                    i++;
                }
                int len = i - start;
                out.write(len - 1);
                out.write(row, start, len);
            }
        }
        return out.toByteArray();
    }

    public static byte[] decodeRow(byte[] encoded, int expectedLength) {
        byte[] out = new byte[expectedLength];
        int pos = 0;
        int i = 0;
        while (i < encoded.length) {
            int c = encoded[i++] & 0xFF;
            if (c == 128) {
                continue; // no-op per spec
            }
            if (c > 128) {
                int count = 257 - c;
                if (i >= encoded.length) {
                    throw new IllegalArgumentException("truncated RLE run");
                }
                byte value = encoded[i++];
                for (int k = 0; k < count; k++) {
                    if (pos >= expectedLength) {
                        throw new IllegalArgumentException("RLE output overflow");
                    }
                    out[pos++] = value;
                }
            } else {
                int count = c + 1;
                if (i + count > encoded.length) {
                    throw new IllegalArgumentException("truncated RLE literal");
                }
                if (pos + count > expectedLength) {
                    throw new IllegalArgumentException("RLE output overflow");
                }
                System.arraycopy(encoded, i, out, pos, count);
                i += count;
                pos += count;
            }
        }
        if (pos != expectedLength) {
            throw new IllegalArgumentException("RLE length mismatch: got " + pos
                    + " expected " + expectedLength);
        }
        return out;
    }
}
