package com.secureprint.core.domain;

import java.time.Instant;
import java.util.List;

/**
 * The content-locked part of a print job: what to print and how, but not where or for whom
 * in a way that is stable across sites. This is what gets sealed into the encrypted spool
 * envelope, so an operator with database access still cannot read document bytes without the
 * spool key.
 */
public record PrintSpec(
        String documentName,
        String mimeType,
        int copies,
        ColorMode colorMode,
        DuplexMode duplex,
        PaperSize paperSize,
        List<Integer> pages,
        boolean staple,
        String documentClass,
        Instant submittedAt) {

    public PrintSpec {
        copies = Math.max(1, Math.min(copies, 99));
        pages = pages == null ? List.of() : List.copyOf(pages);
        paperSize = paperSize == null ? PaperSize.A4 : paperSize;
        colorMode = colorMode == null ? ColorMode.MONO : colorMode;
        duplex = duplex == null ? DuplexMode.SIMPLEX : duplex;
        documentClass = documentClass == null ? "GENERAL" : documentClass;
    }
}
