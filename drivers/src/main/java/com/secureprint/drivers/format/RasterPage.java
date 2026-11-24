package com.secureprint.drivers.format;

import java.awt.image.BufferedImage;

/**
 * One rendered page: a 1-bit bitmap (0 = black ink, 1 = white paper, matching PCL's packing) at
 * a known DPI. Immutable by contract — drivers only read it.
 */
public record RasterPage(BufferedImage bitmap, int dpi, int index) {

    public RasterPage {
        if (bitmap == null || bitmap.getType() != BufferedImage.TYPE_BYTE_BINARY) {
            throw new IllegalArgumentException("raster page must be 1-bit binary");
        }
    }

    public int widthPixels() {
        return bitmap.getWidth();
    }

    public int heightPixels() {
        return bitmap.getHeight();
    }

    /** Scanline stride in bytes, tightly packed. */
    public int strideBytes() {
        return (widthPixels() + 7) / 8;
    }

    /**
     * Extract a tightly packed 1-bit row band. Black pixels are 1-bits in the returned array
     * because both PCL and our own writers expect "1 = ink".
     */
    public byte[] rowBand(int startRow, int rowCount) {
        int stride = strideBytes();
        byte[] out = new byte[stride * rowCount];
        var raster = bitmap.getRaster();
        for (int y = 0; y < rowCount; y++) {
            int srcY = startRow + y;
            if (srcY >= heightPixels()) {
                break;
            }
            for (int x = 0; x < widthPixels(); x++) {
                // TYPE_BYTE_BINARY with a black/white colour model returns sample 0 for black.
                int sample = raster.getSample(x, srcY, 0);
                if (sample == 0) {
                    out[y * stride + (x >>> 3)] |= (byte) (0x80 >>> (x & 7));
                }
            }
        }
        return out;
    }

    public int inkPixelCount() {
        int count = 0;
        int stride = strideBytes();
        for (int row = 0; row < heightPixels(); row += 256) {
            int rows = Math.min(256, heightPixels() - row);
            byte[] band = rowBand(row, rows);
            for (byte b : band) {
                count += Integer.bitCount(b & 0xFF);
            }
        }
        return count;
    }
}
