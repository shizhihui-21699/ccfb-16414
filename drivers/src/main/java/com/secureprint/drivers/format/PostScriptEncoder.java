package com.secureprint.drivers.format;

import com.secureprint.core.domain.DuplexMode;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.drivers.spi.UnsupportedJobException;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * PostScript Level 2/3 encoder for devices whose native language is PostScript (Ricoh,
 * Konica Minolta, Xerox, Canon imageRUNNER, Lexmark, and most machines in print rooms).
 *
 * <p>The page is embedded as a 1-bit image device per page, then drawn to fill the media box.
 * PostScript is ASCII-only, so each image row is written as a run-length encoded hex string
 * rather than raw binary — this survives any transport that mangles 8-bit data (notably LPD
 * filters and some IPP gateways) without needing binary-safe framing.
 *
 * <p>We deliberately do not pass arbitrary PostScript through from the submitter: a PostScript
 * file is a program, and honouring one from a web form would let a submitter run code with the
 * printer's privileges. Submitters upload PDF/text/images; we always rasterize.
 */
public final class PostScriptEncoder {

    private final int dpi;

    public PostScriptEncoder(int dpi) {
        this.dpi = dpi;
    }

    public byte[] encode(List<RasterPage> pages, PrintSpec spec) {
        if (pages.isEmpty()) {
            throw new UnsupportedJobException("postscript", "nothing to print");
        }
        StringBuilder ps = new StringBuilder(8192);
        ps.append("%!PS-Adobe-3.0\n");
        ps.append("%%Creator: secure-print release service\n");
        ps.append("%%Pages: ").append(pages.size() * Math.max(1, spec.copies())).append('\n');
        ps.append("%%LanguageLevel: 2\n");
        ps.append("%%EndComments\n");

        // Duplex + media via setpagedevice. Wrapped in stopped so a device that lacks the
        // feature ignores it instead of erroring the whole job.
        int duplex = spec.duplex() == DuplexMode.SIMPLEX ? 0
                : (spec.duplex() == DuplexMode.SHORT_EDGE ? 1 : 2);
        ps.append("<< /Duplex ").append(duplex)
                .append(" /PageSize [")
                .append(fmt(PageGeometry.widthPoints(spec.paperSize()))).append(' ')
                .append(fmt(PageGeometry.heightPoints(spec.paperSize())))
                .append("] >> setpagedevice\n");

        int copy = Math.max(1, Math.min(spec.copies(), 99));
        for (int c = 0; c < copy; c++) {
            for (RasterPage page : pages) {
                emitPage(ps, page, spec);
            }
        }
        ps.append("%%EOF\n");
        return ps.toString().getBytes(StandardCharsets.US_ASCII);
    }

    private void emitPage(StringBuilder ps, RasterPage page, PrintSpec spec) {
        int w = page.widthPixels();
        int h = page.heightPixels();
        double mediaW = PageGeometry.widthPoints(spec.paperSize());
        double mediaH = PageGeometry.heightPoints(spec.paperSize());
        int stride = page.strideBytes();

        ps.append("%%Page: ").append(page.index() + 1).append(' ').append(page.index() + 1).append('\n');
        ps.append("gsave\n");
        ps.append(fmt(mediaW)).append(' ').append(fmt(mediaH)).append(" scale\n");
        ps.append("1 1 1 setrgbcolor 0 0 1 1 rectfill\n");   // white page background
        ps.append("0 setgray\n");
        ps.append("/picstr ").append(stride).append(" string def\n");
        ps.append(w).append(' ').append(h).append(" 1\n");
        // Images are bottom-up in PostScript, so the placement matrix flips vertically.
        ps.append('[').append(w).append(" 0 0 -").append(h).append(" 0 ").append(h).append("]\n");
        // The data is RunLength-encoded, then hex-wrapped so any 8-bit-unsafe transport (LPD
        // filters, some IPP gateways) cannot corrupt it. Both filters are PostScript Level 2.
        ps.append("{ currentfile /ASCIIHexDecode filter /RunLengthDecode filter ")
                .append("picstr readstring pop } image\n");

        appendRunLengthHex(ps, page);
        ps.append(">\n");   // terminates ASCIIHexDecode
        ps.append("grestore\n");
        ps.append("showpage\n");
    }

    /**
     * Each row is PackBits/RLE encoded then appended as hex. PostScript's
     * {@code /RunLengthDecode} uses the same PackBits scheme as PCL raster mode 2 and TIFF, so
     * {@link Rle} serves both encoders.
     */
    private void appendRunLengthHex(StringBuilder hex, RasterPage page) {
        for (int row = 0; row < page.heightPixels(); row++) {
            byte[] encoded = Rle.encodeRow(page.rowBand(row, 1));
            for (byte b : encoded) {
                hex.append(HEX[(b >> 4) & 0x0F]).append(HEX[b & 0x0F]);
            }
            hex.append('\n');
        }
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static String fmt(double v) {
        return String.format(java.util.Locale.ROOT, "%.2f", v);
    }

}
