package com.secureprint.drivers.format;

import com.secureprint.core.domain.PaperSize;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.drivers.spi.UnsupportedJobException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.text.PDFTextStripper;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Turns any supported document into 1-bit {@link RasterPage}s.
 *
 * <p>Supported inputs and why each is handled the way it is:
 * <ul>
 *   <li><b>PDF</b> — rasterized with PDFBox. We deliberately do not pass PDF through to the
 *       device: a printer with a PostScript interpreter would happily execute embedded
 *       JavaScript and forms, which widens the attack surface for a document the applicant can
 *       influence (e.g. a contract template filled from a web form). Rasterizing flattens it.</li>
 *   <li><b>Plain text</b> — laid out with a monospaced font. Payroll exports and "print to
 *       secure print" from legacy ERP systems are usually plain text.</li>
 *   <li><b>PNG/JPEG</b> — thresholded to 1-bit; used for scanned signed contracts.</li>
 * </ul>
 *
 * <p>Unknown types are rejected rather than guessed, because silently printing garbage on a
 * payroll document is worse than telling the employee the format is unsupported.
 */
public final class DocumentRasterizer {

    private final int dpi;

    public DocumentRasterizer(int dpi) {
        if (dpi < 150 || dpi > 1200) {
            throw new IllegalArgumentException("dpi out of supported range");
        }
        this.dpi = dpi;
    }

    public static DocumentRasterizer standard() {
        return new DocumentRasterizer(PageGeometry.DEFAULT_DPI);
    }

    public List<RasterPage> render(byte[] document, String mimeType, String fileName, PrintSpec spec) {
        String type = classify(document, mimeType, fileName);
        return switch (type) {
            case "application/pdf" -> renderPdf(document, spec);
            case "text/plain" -> renderText(document, spec);
            case "image/png", "image/jpeg" -> renderImage(document, spec);
            default -> throw new UnsupportedJobException("rasterizer",
                    "unsupported document type " + type);
        };
    }

    private static String classify(byte[] doc, String mimeType, String fileName) {
        if (doc.length >= 5 && doc[0] == '%' && doc[1] == 'P' && doc[2] == 'D' && doc[3] == 'F') {
            return "application/pdf";
        }
        if (doc.length >= 3 && (doc[0] & 0xFF) == 0x89 && doc[1] == 'P' && doc[2] == 'N') {
            return "image/png";
        }
        if (doc.length >= 2 && (doc[0] & 0xFF) == 0xFF && (doc[1] & 0xFF) == 0xD8) {
            return "image/jpeg";
        }
        if (mimeType != null && !mimeType.isBlank()) {
            return mimeType.toLowerCase(java.util.Locale.ROOT);
        }
        String lower = fileName == null ? "" : fileName.toLowerCase(java.util.Locale.ROOT);
        if (lower.endsWith(".pdf")) {
            return "application/pdf";
        }
        if (lower.endsWith(".png")) {
            return "image/png";
        }
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
            return "image/jpeg";
        }
        return "text/plain";
    }

    private List<RasterPage> renderPdf(byte[] pdf, PrintSpec spec) {
        List<RasterPage> pages = new ArrayList<>();
        try (PDDocument doc = PDDocument.load(pdf)) {
            if (doc.isEncrypted()) {
                throw new UnsupportedJobException("rasterizer",
                        "password-protected PDFs must be decrypted before submission");
            }
            PDFRenderer renderer = new PDFRenderer(doc);
            int count = doc.getNumberOfPages();
            List<Integer> wanted = spec.pages();
            for (int i = 0; i < count; i++) {
                int pageNo = i + 1;
                if (!wanted.isEmpty() && !wanted.contains(pageNo)) {
                    continue;
                }
                BufferedImage img = renderer.renderImageWithDPI(i, dpi, ImageType.BINARY);
                pages.add(new RasterPage(toBinary(img), dpi, pages.size()));
            }
        } catch (InvalidPasswordException e) {
            throw new UnsupportedJobException("rasterizer", "encrypted PDF");
        } catch (IOException e) {
            throw new UnsupportedJobException("rasterizer", "cannot parse PDF: " + e.getMessage());
        }
        if (pages.isEmpty()) {
            throw new UnsupportedJobException("rasterizer",
                    "no pages selected (PDF has " + countOrZero(pdf) + " pages)");
        }
        return pages;
    }

    private static int countOrZero(byte[] pdf) {
        try (PDDocument d = PDDocument.load(pdf)) {
            return d.getNumberOfPages();
        } catch (IOException e) {
            return 0;
        }
    }

    /** Re-draw any image onto a clean 1-bit surface so stray alpha/colour models cannot slip through. */
    private static BufferedImage toBinary(BufferedImage src) {
        int w = src.getWidth();
        int h = src.getHeight();
        BufferedImage out = new BufferedImage(w, h, BufferedImage.TYPE_BYTE_BINARY);
        Graphics2D g = out.createGraphics();
        try {
            g.setColor(Color.WHITE);
            g.fillRect(0, 0, w, h);
            g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
            g.drawImage(src, 0, 0, null);
        } finally {
            g.dispose();
        }
        return out;
    }

    private List<RasterPage> renderImage(byte[] image, PrintSpec spec) {
        BufferedImage src;
        try {
            src = ImageIO.read(new ByteArrayInputStream(image));
        } catch (IOException e) {
            throw new UnsupportedJobException("rasterizer", "cannot decode image");
        }
        if (src == null) {
            throw new UnsupportedJobException("rasterizer", "unrecognised image encoding");
        }
        int pw = PageGeometry.widthPixels(spec.paperSize(), dpi);
        int ph = PageGeometry.heightPixels(spec.paperSize(), dpi);
        double scale = Math.min((double) pw / src.getWidth(), (double) ph / src.getHeight());
        int dw = Math.max(1, (int) (src.getWidth() * scale));
        int dh = Math.max(1, (int) (src.getHeight() * scale));

        BufferedImage page = new BufferedImage(pw, ph, BufferedImage.TYPE_BYTE_BINARY);
        Graphics2D g = page.createGraphics();
        try {
            g.setColor(Color.WHITE);
            g.fillRect(0, 0, pw, ph);
            g.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                    RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            g.drawImage(src, (pw - dw) / 2, (ph - dh) / 2, dw, dh, null);
        } finally {
            g.dispose();
        }
        return List.of(new RasterPage(page, dpi, 0));
    }

    private List<RasterPage> renderText(byte[] text, PrintSpec spec) {
        String content = new String(text, StandardCharsets.UTF_8);
        // Normalise line endings and strip control characters that could inject PCL/PS escapes
        // through a print job (e.g. a CSV field containing 0x1B).
        content = content.replace("\r\n", "\n").replace('\r', '\n')
                .replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");

        int dpi = this.dpi;
        int margin = (int) Math.round(dpi * 0.75);      // 3/4 inch margins
        int fontSizePx = (int) Math.round(dpi * 11.0 / 72.0); // 11pt
        int lineHeight = (int) Math.round(fontSizePx * 1.35);
        int pw = PageGeometry.widthPixels(spec.paperSize(), dpi);
        int ph = PageGeometry.heightPixels(spec.paperSize(), dpi);
        int usableHeight = ph - 2 * margin;
        int linesPerPage = Math.max(1, usableHeight / lineHeight);

        String[] lines = content.split("\n", -1);
        // Pre-wrap long lines by character count so nothing is silently clipped.
        int charWidth = Math.max(1, (int) Math.round(fontSizePx * 0.6));
        int cols = Math.max(20, (pw - 2 * margin) / charWidth);
        List<String> wrapped = new ArrayList<>();
        for (String line : lines) {
            if (line.length() <= cols) {
                wrapped.add(line);
                continue;
            }
            for (int i = 0; i < line.length(); i += cols) {
                wrapped.add(line.substring(i, Math.min(line.length(), i + cols)));
            }
        }

        List<RasterPage> pages = new ArrayList<>();
        List<Integer> wanted = spec.pages();
        int pageIndex = 0;
        for (int start = 0; start < Math.max(1, wrapped.size()); start += linesPerPage) {
            pageIndex++;
            if (!wanted.isEmpty() && !wanted.contains(pageIndex)) {
                continue;
            }
            BufferedImage page = new BufferedImage(pw, ph, BufferedImage.TYPE_BYTE_BINARY);
            Graphics2D g = page.createGraphics();
            try {
                g.setColor(Color.WHITE);
                g.fillRect(0, 0, pw, ph);
                g.setColor(Color.BLACK);
                g.setFont(new Font(Font.MONOSPACED, Font.PLAIN, fontSizePx));
                g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                        RenderingHints.VALUE_TEXT_ANTIALIAS_OFF);
                int y = margin + fontSizePx;
                for (int i = start; i < Math.min(wrapped.size(), start + linesPerPage); i++) {
                    g.drawString(wrapped.get(i), margin, y);
                    y += lineHeight;
                }
            } finally {
                g.dispose();
            }
            pages.add(new RasterPage(page, dpi, pages.size()));
        }
        return pages;
    }

    /** Extracts text for the release terminal's confirmation preview; empty for non-text docs. */
    public String previewText(byte[] pdf, int maxChars) {
        try (PDDocument doc = PDDocument.load(pdf)) {
            PDFTextStripper stripper = new PDFTextStripper();
            stripper.setEndPage(Math.min(1, doc.getNumberOfPages()));
            String text = stripper.getText(doc);
            return text.length() <= maxChars ? text : text.substring(0, maxChars) + "…";
        } catch (IOException e) {
            return "";
        }
    }

    public static int firstPageOrientation(byte[] pdf) {
        try (PDDocument doc = PDDocument.load(pdf)) {
            PDPage page = doc.getPage(0);
            return page.getRotation() % 180;
        } catch (IOException e) {
            return 0;
        }
    }

    public static PaperSize detectPaperSize(byte[] pdf, PaperSize fallback) {
        try (PDDocument doc = PDDocument.load(pdf)) {
            PDPage page = doc.getPage(0);
            var box = page.getMediaBox();
            float w = Math.min(box.getWidth(), box.getHeight());
            float h = Math.max(box.getWidth(), box.getHeight());
            if (Math.abs(w - 595.28f) < 10 && Math.abs(h - 841.89f) < 10) {
                return PaperSize.A4;
            }
            if (Math.abs(w - 841.89f) < 10 && Math.abs(h - 1190.55f) < 10) {
                return PaperSize.A3;
            }
            if (Math.abs(w - 612f) < 10 && Math.abs(h - 792f) < 10) {
                return PaperSize.LETTER;
            }
            return fallback;
        } catch (IOException e) {
            return fallback;
        }
    }
}
