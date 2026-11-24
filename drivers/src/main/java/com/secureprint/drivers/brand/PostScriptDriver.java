package com.secureprint.drivers.brand;

import com.secureprint.drivers.format.DocumentRasterizer;
import com.secureprint.drivers.format.PostScriptEncoder;
import com.secureprint.drivers.format.RasterPage;
import com.secureprint.drivers.spi.DeliveryResult;
import com.secureprint.drivers.spi.DeviceSession;
import com.secureprint.drivers.spi.PrinterDriver;
import com.secureprint.drivers.spi.RenderRequest;
import com.secureprint.drivers.transport.RawTcpTransport;

import java.util.List;
import java.util.Set;

/**
 * Generic PostScript-over-raw-9100 driver.
 *
 * <p>Used for devices that are PostScript-native and do not have a reliable PCL path: Canon
 * imageRUNNER (PS/PCL both available but PS preferred for colour accuracy), Konica Minolta
 * bizhub in PS mode, Xerox WorkCentre/VersaLink, Sharp MX, Toshiba e-STUDIO, and OKI.
 *
 * <p>These brands get one class each in production (to record model-specific quirks like staple
 * offsets), but they all share this encoder. The demo registers a couple of concrete brands to
 * show the registration pattern.
 */
public class PostScriptDriver implements PrinterDriver {

    protected final DocumentRasterizer rasterizer;
    protected final int dpi;
    private final String driverId;
    private final String description;
    private final Set<String> features;

    public PostScriptDriver(String driverId, String description, int dpi, Set<String> features) {
        this.driverId = driverId;
        this.description = description;
        this.dpi = dpi;
        this.features = Set.copyOf(features);
        this.rasterizer = new DocumentRasterizer(dpi);
    }

    @Override
    public String driverId() {
        return driverId;
    }

    @Override
    public String description() {
        return description;
    }

    @Override
    public Set<String> supportedFeatures() {
        return features;
    }

    @Override
    public com.secureprint.drivers.spi.DeviceStatus probe(DeviceSession session) {
        try {
            String reply = RawTcpTransport.pjlStatus(session);
            if (reply == null || reply.isBlank()) {
                return com.secureprint.drivers.spi.DeviceStatus.offline("no PJL reply");
            }
            String lower = reply.toLowerCase(java.util.Locale.ROOT);
            var status = lower.contains("ready") || lower.contains("idle")
                    ? com.secureprint.core.domain.PrinterStatus.IDLE
                    : lower.contains("busy") || lower.contains("printing")
                    ? com.secureprint.core.domain.PrinterStatus.BUSY
                    : com.secureprint.core.domain.PrinterStatus.ONLINE;
            return new com.secureprint.drivers.spi.DeviceStatus(status, reply.trim(),
                    java.util.Map.of());
        } catch (RuntimeException e) {
            return com.secureprint.drivers.spi.DeviceStatus.offline(e.getMessage());
        }
    }

    @Override
    public DeliveryResult deliver(DeviceSession session, RenderRequest request) {
        List<RasterPage> pages = rasterizer.render(request.documentBytes(), request.mimeType(),
                request.documentName(), request.spec());
        byte[] ps = new PostScriptEncoder(dpi).encode(pages, request.spec());
        int sent = RawTcpTransport.send(session, ps);
        return new DeliveryResult(request.jobId(), pages.size(), sent, "PostScript-3");
    }

    @Override
    public void cancel(DeviceSession session, String deviceJobId) {
        RawTcpTransport.send(session, "\u0004\u0004".getBytes(
                java.nio.charset.StandardCharsets.ISO_8859_1));  // PS ^D ^D = end job
    }
}
