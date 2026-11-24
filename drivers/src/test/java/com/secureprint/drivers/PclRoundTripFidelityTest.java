package com.secureprint.drivers;

import com.secureprint.core.domain.ColorMode;
import com.secureprint.core.domain.DuplexMode;
import com.secureprint.core.domain.PaperSize;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.drivers.format.DocumentRasterizer;
import com.secureprint.drivers.format.PclEncoder;
import com.secureprint.drivers.format.RasterPage;
import com.secureprint.drivers.format.Rle;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reconstructs the bitmap a printer would actually render from the PCL stream, and checks the
 * document content survived the whole pipeline: text layout → 1-bit raster → PackBits → PCL
 * framing. Without this, a bug in the RLE encoder or the row-band extraction could ship blank
 * pages and every other test would still pass.
 */
class PclRoundTripFidelityTest {

    private static final int DPI = 300;

    private static PrintSpec spec() {
        return new PrintSpec("p.txt", "text/plain", 1, ColorMode.MONO, DuplexMode.SIMPLEX,
                PaperSize.A5, List.of(), false, "GENERAL", Instant.now());
    }

    /** A crude but faithful PCL raster reader: walks ESC*b<n>W rows and decodes each. */
    private record PclImage(int width, int height, List<byte[]> rows) {
        int inkPixels() {
            int ink = 0;
            for (byte[] row : rows) {
                for (byte b : row) {
                    ink += Integer.bitCount(b & 0xFF);
                }
            }
            return ink;
        }
    }

    private static PclImage decodePcl(byte[] pcl) {
        String s = new String(pcl, StandardCharsets.ISO_8859_1);
        int width = 0;
        int height = 0;
        // Source width/height from ESC*r<n>S and ESC*r<n>T
        java.util.regex.Matcher w = java.util.regex.Pattern
                .compile("\u001B\\*r(\\d+)S").matcher(s);
        if (w.find()) {
            width = Integer.parseInt(w.group(1));
        }
        java.util.regex.Matcher h = java.util.regex.Pattern
                .compile("\u001B\\*r(\\d+)T").matcher(s);
        if (h.find()) {
            height = Integer.parseInt(h.group(1));
        }

        List<byte[]> rows = new ArrayList<>();
        int stride = (width + 7) / 8;
        int i = 0;
        byte[] b = pcl;
        while (i < b.length - 3) {
            if (b[i] == 0x1B && b[i + 1] == '*' && b[i + 2] == 'b') {
                int j = i + 3;
                int len = 0;
                boolean digits = false;
                while (j < b.length && b[j] >= '0' && b[j] <= '9') {
                    len = len * 10 + (b[j] - '0');
                    digits = true;
                    j++;
                }
                if (digits && j < b.length && b[j] == 'W' && len > 0
                        && j + 1 + len <= b.length) {
                    byte[] encoded = java.util.Arrays.copyOfRange(b, j + 1, j + 1 + len);
                    rows.add(Rle.decodeRow(encoded, stride));
                    i = j + 1 + len;
                    continue;
                }
            }
            i++;
        }
        return new PclImage(width, height, rows);
    }

    @Test
    void textContentSurvivesRasterToPcl() {
        String doc = "ACME CORP\nPAYSLIP 2026-11\nNET 12345.67";
        List<RasterPage> pages = new DocumentRasterizer(DPI).render(
                doc.getBytes(StandardCharsets.UTF_8), "text/plain", "p.txt", spec());
        RasterPage page = pages.get(0);

        byte[] pcl = new PclEncoder(DPI).encode(pages, spec());
        PclImage image = decodePcl(pcl);

        assertEquals(page.widthPixels(), image.width());
        assertEquals(page.heightPixels(), image.height());
        assertEquals(page.heightPixels(), image.rows().size(),
                "one raster row must arrive per page row");
        assertTrue(image.inkPixels() > 500, "the page must contain real glyph ink");

        // Stronger check: every ink pixel in the decoder output must equal the source page's ink.
        assertEquals(page.inkPixelCount(), image.inkPixels(),
                "decoded raster must match the source page exactly");
    }

    @Test
    void blankPageStaysBlankAfterEncoding() {
        List<RasterPage> pages = new DocumentRasterizer(DPI).render(new byte[0], "text/plain",
                "empty.txt", spec());
        byte[] pcl = new PclEncoder(DPI).encode(pages, spec());
        PclImage image = decodePcl(pcl);
        assertEquals(0, image.inkPixels(), "an empty document must produce a blank page");
    }

    @Test
    void everyRowIsByteIdenticalToSource() {
        List<RasterPage> pages = new DocumentRasterizer(DPI).render(
                "Row-by-row fidelity check".getBytes(StandardCharsets.UTF_8), "text/plain",
                "p.txt", spec());
        RasterPage page = pages.get(0);
        byte[] pcl = new PclEncoder(DPI).encode(pages, spec());
        PclImage image = decodePcl(pcl);

        for (int row = 0; row < page.heightPixels(); row++) {
            byte[] expected = page.rowBand(row, 1);
            assertTrue(java.util.Arrays.equals(expected, image.rows().get(row)),
                    "raster row " + row + " differs after encode/decode");
        }
    }

    @Test
    void postScriptHexPayloadHasNoNonAscii() {
        List<RasterPage> pages = new DocumentRasterizer(DPI).render(
                "ps fidelity".getBytes(StandardCharsets.UTF_8), "text/plain", "p.txt", spec());
        byte[] ps = new com.secureprint.drivers.format.PostScriptEncoder(DPI)
                .encode(pages, spec());
        ByteArrayOutputStream nonAscii = new ByteArrayOutputStream();
        for (byte x : ps) {
            if (x < 0 || x > 127) {
                nonAscii.write(x);
            }
        }
        assertEquals(0, nonAscii.size(), "PS payload must survive 7-bit transports");
    }
}
