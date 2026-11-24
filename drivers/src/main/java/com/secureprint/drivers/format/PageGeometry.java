package com.secureprint.drivers.format;

import com.secureprint.core.domain.PaperSize;

/**
 * Page geometry in device-independent units (1/72 inch, i.e. PostScript points) and the
 * 1-bit raster resolution used to bridge arbitrary input documents to PDLs that only accept
 * raster or text.
 *
 * <p>The raster bridge matters: enterprise fleets contain printers whose only reliable,
 * driverless path is "send a bitmap". Rather than ship a different converter per brand, we
 * render once to a 1-bit page bitmap at the device's native resolution and then let a thin
 * brand-specific encoder wrap it. 600 dpi is the sweet spot: readable text, ~50 KB/page
 * compressed, and accepted by every PCL/PS device made since ~2005.
 */
public final class PageGeometry {

    public static final int DEFAULT_DPI = 600;

    private PageGeometry() {
    }

    public static double widthPoints(PaperSize size) {
        return switch (size) {
            case A4 -> 595.28;
            case A3 -> 841.89;
            case A5 -> 419.53;
            case LETTER -> 612.0;
            case LEGAL -> 612.0;
            case CARD -> 242.0;
        };
    }

    public static double heightPoints(PaperSize size) {
        return switch (size) {
            case A4 -> 841.89;
            case A3 -> 1190.55;
            case A5 -> 595.28;
            case LETTER -> 792.0;
            case LEGAL -> 1008.0;
            case CARD -> 153.0;
        };
    }

    public static int widthPixels(PaperSize size, int dpi) {
        return (int) Math.round(widthPoints(size) / 72.0 * dpi);
    }

    public static int heightPixels(PaperSize size, int dpi) {
        return (int) Math.round(heightPoints(size) / 72.0 * dpi);
    }

    /** PCL/PS physical media selector names. */
    public static String pclMediaName(PaperSize size) {
        return switch (size) {
            case A4 -> "A4";
            case A3 -> "A3";
            case A5 -> "A5";
            case LETTER -> "LETTER";
            case LEGAL -> "LEGAL";
            case CARD -> "CARD";
        };
    }

    public static String postScriptMediaName(PaperSize size) {
        return switch (size) {
            case A4 -> "a4";
            case A3 -> "a3";
            case A5 -> "a5";
            case LETTER -> "letter";
            case LEGAL -> "legal";
            case CARD -> "indexcard";
        };
    }
}
