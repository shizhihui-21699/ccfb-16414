package com.secureprint.drivers.format;

import com.secureprint.core.domain.ColorMode;
import com.secureprint.core.domain.DuplexMode;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.drivers.spi.UnsupportedJobException;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * PCL5 (PCL5e/c-compatible) raster encoder.
 *
 * <p>PCL5 is the most widely implemented device language in the enterprise fleet — HP LaserJet,
 * Kyocera, Brother, Lexmark, Konica Minolta, Ricoh, Sharp, Toshiba and most rebadges accept it.
 * Rendering the page to a raster and shipping that (rather than text with font commands) avoids
 * the font-metric mismatch that makes the same job look different on every brand, which matters
 * when a payroll slip must be identical whether it is collected in Shanghai or Munich.
 *
 * <p>Rows are TIFF-RLE compressed (compression mode 2). Uncompressed 1-bit A4 at 600 dpi is
 * ~4.3 MB per page; a typical payslip compresses to well under 100 KB.
 *
 * <p>Each page ends with an explicit form feed so a device that ignores the duplex command still
 * produces correct single-sided output instead of overlaying two pages.
 */
public final class PclEncoder {

    private static final char ESC = 0x1B;
    /** Bands are irrelevant for PCL5 (rows are sent individually); kept for API symmetry. */

    private final int dpi;

    public PclEncoder(int dpi) {
        this.dpi = dpi;
    }

    public byte[] encode(List<RasterPage> pages, PrintSpec spec) {
        if (pages.isEmpty()) {
            throw new UnsupportedJobException("pcl5", "nothing to print");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(64 * 1024);

        // Universal Exit Language + PJL job wrapper. UEL is the single most important line when
        // many applications share one printer: it discards interpreter state left by the last job.
        out.writeBytes("\u001B%-12345X@PJL JOB NAME=\"secure-print\"\r\n"
                .getBytes(StandardCharsets.ISO_8859_1));
        out.writeBytes("\u001B%-12345X".getBytes(StandardCharsets.ISO_8859_1));
        write(out, "\u001BE");                                   // PCL reset
        write(out, "\u001B&l" + paperSizeCode(spec) + "A");      // media size
        write(out, "\u001B&l0H");                                // paper source auto
        write(out, "\u001B&l0O");                                // portrait
        if (spec.duplex() != DuplexMode.SIMPLEX) {
            write(out, "\u001B&l1S");                            // duplex, long edge
            if (spec.duplex() == DuplexMode.SHORT_EDGE) {
                write(out, "\u001B&l2S");                        // short edge binding
            }
        }
        if (spec.colorMode() == ColorMode.MONO) {
            write(out, "\u001B&b0M");                            // monochrome
        }

        int copies = Math.max(1, Math.min(spec.copies(), 99));
        for (RasterPage page : pages) {
            for (int copy = 0; copy < copies; copy++) {
                encodePage(out, page);
            }
        }

        write(out, "\u001BE");
        out.writeBytes("\u001B%-12345X@PJL EOJ\r\n".getBytes(StandardCharsets.ISO_8859_1));
        out.writeBytes("\u001B%-12345X".getBytes(StandardCharsets.ISO_8859_1));
        return out.toByteArray();
    }

    private void encodePage(ByteArrayOutputStream out, RasterPage page) {
        int w = page.widthPixels();
        int h = page.heightPixels();
        write(out, "\u001B*t" + dpi + "R");                      // raster resolution
        write(out, "\u001B*r1A");                                // start raster graphics
        write(out, "\u001B*r" + w + "S");                        // source width in pixels
        write(out, "\u001B*r" + h + "T");                        // source height in pixels
        write(out, "\u001B*b2M");                                // compression: TIFF RLE

        for (int row = 0; row < h; row++) {
            byte[] raw = page.rowBand(row, 1);
            byte[] encoded = Rle.encodeRow(raw);
            out.write(ESC);
            out.write('*');
            out.write('b');
            writeAscii(out, Integer.toString(encoded.length));
            out.write('W');
            out.write(encoded, 0, encoded.length);
        }
        write(out, "\u001B*rB");                                 // end raster graphics
        write(out, "\u000C");                                    // form feed
    }

    private static String paperSizeCode(PrintSpec spec) {
        return switch (spec.paperSize()) {
            case A4 -> "26";
            case A3 -> "27";
            case A5 -> "25";
            case LETTER -> "2";
            case LEGAL -> "3";
            case CARD -> "26";
        };
    }

    private static void write(ByteArrayOutputStream out, String ascii) {
        out.writeBytes(ascii.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static void writeAscii(ByteArrayOutputStream out, String s) {
        out.writeBytes(s.getBytes(StandardCharsets.US_ASCII));
    }
}
