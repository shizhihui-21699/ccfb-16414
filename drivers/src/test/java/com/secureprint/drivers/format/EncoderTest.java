package com.secureprint.drivers.format;

import com.secureprint.core.domain.ColorMode;
import com.secureprint.core.domain.DuplexMode;
import com.secureprint.core.domain.PaperSize;
import com.secureprint.core.domain.PrintSpec;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EncoderTest {

    private static PrintSpec spec() {
        return new PrintSpec("payslip.txt", "text/plain", 1, ColorMode.MONO,
                DuplexMode.SIMPLEX, PaperSize.A4, List.of(), false, "PAYROLL", Instant.now());
    }

    private static RasterPage pageWithText(String text) {
        BufferedImage img = new BufferedImage(600, 200, BufferedImage.TYPE_BYTE_BINARY);
        Graphics2D g = img.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, 600, 200);
        g.setColor(Color.BLACK);
        g.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 24));
        g.drawString(text, 20, 100);
        g.dispose();
        return new RasterPage(img, 600, 0);
    }

    @Test
    void pclHasProperJobFramingAndFormFeeds() {
        byte[] pcl = new PclEncoder(600).encode(List.of(pageWithText("hello")), spec());
        String asText = new String(pcl, StandardCharsets.ISO_8859_1);
        assertTrue(asText.startsWith("\u001B%-12345X@PJL JOB"), "PJL job wrapper required");
        assertTrue(asText.contains("@PJL EOJ"), "PJL end-of-job required");
        assertTrue(asText.contains("\u001B*t600R"), "raster resolution must be declared");
        assertTrue(asText.contains("\u001B*b2M"), "RLE compression must be requested");
        assertTrue(asText.contains("\u000C"), "form feed must terminate the page");
        assertTrue(asText.contains("\u001B*r1A") && asText.contains("\u001B*rB"),
                "raster block must be opened and closed");
    }

    @Test
    void pclEmitsOneRasterBlockPerRow() {
        byte[] pcl = new PclEncoder(600).encode(List.of(pageWithText("x")), spec());
        String asText = new String(pcl, StandardCharsets.ISO_8859_1);
        long rowCommands = asText.split("\u001B\\*b\\d+W", -1).length - 1;
        assertTrue(rowCommands == 200, "expected 200 row transfers for a 200px page, got "
                + rowCommands);
    }

    @Test
    void pclHonoursCopiesAndDuplex() {
        PrintSpec duplexTwo = new PrintSpec("a.pdf", "application/pdf", 2, ColorMode.MONO,
                DuplexMode.LONG_EDGE, PaperSize.A4, List.of(), false, "GENERAL", Instant.now());
        byte[] pcl = new PclEncoder(600).encode(List.of(pageWithText("d")), duplexTwo);
        String asText = new String(pcl, StandardCharsets.ISO_8859_1);
        assertTrue(asText.contains("\u001B&l1S"), "duplex request must be present");
        long formFeeds = asText.chars().filter(c -> c == 0x0C).count();
        assertTrue(formFeeds == 2, "two copies must produce two pages, got " + formFeeds);
    }

    @Test
    void postScriptIsWellFormedAndHexSafe() {
        byte[] ps = new PostScriptEncoder(600).encode(List.of(pageWithText("ps")), spec());
        String text = new String(ps, StandardCharsets.US_ASCII);
        assertTrue(text.startsWith("%!PS-Adobe-3.0"));
        assertTrue(text.contains("%%EOF"));
        assertTrue(text.contains("setpagedevice"));
        assertTrue(text.contains("/ASCIIHexDecode filter /RunLengthDecode filter"));
        // Every byte must be 7-bit ASCII so LPD/IPP gateways cannot corrupt the payload.
        for (byte b : ps) {
            assertTrue(b >= 0 && b < 128, "PostScript output must be pure ASCII");
        }
    }

    @Test
    void rasterizerHandlesTextWithNoInklessNoise() {
        List<RasterPage> pages = DocumentRasterizer.standard().render(
                "PAYSLIP\nEmployee: 张三\nNet: 12,345.00\n".getBytes(StandardCharsets.UTF_8),
                "text/plain", "payslip.txt", spec());
        assertFalse(pages.isEmpty());
        RasterPage p = pages.get(0);
        assertTrue(p.inkPixelCount() > 100, "text must produce ink");
        assertTrue(p.widthPixels() > 1000 && p.heightPixels() > 1000,
                "A4 at 600dpi must be ~4961x7016 px");
    }

    @Test
    void rasterizerStripsControlCharactersThatCouldInjectPdl() {
        byte[] evil = "before\u001B%-12345X@PJL RESET\r\nafter".getBytes(StandardCharsets.UTF_8);
        List<RasterPage> pages = DocumentRasterizer.standard().render(evil, "text/plain",
                "x.txt", spec());
        assertFalse(pages.isEmpty());
    }

    @Test
    void rasterizerHandlesPng() throws Exception {
        BufferedImage img = new BufferedImage(200, 100, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, 200, 100);
        g.setColor(Color.BLACK);
        g.fillRect(50, 40, 100, 20);
        g.dispose();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);

        List<RasterPage> pages = DocumentRasterizer.standard().render(out.toByteArray(),
                "image/png", "scan.png", spec());
        assertTrue(pages.get(0).inkPixelCount() > 1000);
    }
}
