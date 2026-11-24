package com.secureprint.drivers.brand;

import com.secureprint.core.domain.PrinterStatus;
import com.secureprint.drivers.format.DocumentRasterizer;
import com.secureprint.drivers.format.PclEncoder;
import com.secureprint.drivers.spi.DeliveryResult;
import com.secureprint.drivers.spi.DeviceSession;
import com.secureprint.drivers.spi.DeviceStatus;
import com.secureprint.drivers.spi.DriverException;
import com.secureprint.drivers.spi.PrinterDriver;
import com.secureprint.drivers.spi.RenderRequest;
import com.secureprint.drivers.transport.RawTcpTransport;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Base for every driver that ships PCL5 raster over a raw socket (port 9100). This covers the
 * majority of the fleet: HP LaserJet/Color LaserJet, Kyocera ECOSYS/TASKalfa, Brother HL/MFC,
 * Lexmark, Samsung/Xerox rebadges, Konica Minolta bizhub in PCL mode, Ricoh Aficio in PCL mode.
 *
 * <p>Brand subclasses only override the device-specific bits: which PJL status keywords mean
 * "ready", whether the model accepts PCL5c colour, and how to interpret vendor payloads in the
 * status reply. Everything about rendering, encryption and release lives above this layer, so
 * adding a brand is a ~30-line class plus a registry entry.
 */
public abstract class PclRawSocketDriver implements PrinterDriver {

    protected final DocumentRasterizer rasterizer;
    protected final int dpi;

    protected PclRawSocketDriver(int dpi) {
        this.dpi = dpi;
        this.rasterizer = new DocumentRasterizer(dpi);
    }

    @Override
    public Set<String> supportedFeatures() {
        return Set.of("MONO", "COLOR", "DUPLEX", "A4", "A3", "LETTER", "LEGAL", "STAPLE");
    }

    @Override
    public DeviceStatus probe(DeviceSession session) {
        try {
            String reply = RawTcpTransport.pjlStatus(session);
            return interpret(reply);
        } catch (DriverException e) {
            return DeviceStatus.offline(e.getMessage());
        }
    }

    /**
     * Map a PJL {@code INFO STATUS} reply to a status.
     *
     * <p>The reply looks like {@code @PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY="Ready"\r\n}.
     * Vendors differ in the exact strings but the {@code CODE} values and the {@code DISPLAY}
     * keywords are close enough to share a default; each brand subclass may widen the keyword
     * set without duplicating the transport.
     */
    protected DeviceStatus interpret(String reply) {
        String lower = reply == null ? "" : reply.toLowerCase(Locale.ROOT);
        if (lower.isBlank()) {
            return new DeviceStatus(PrinterStatus.OFFLINE, "no PJL reply", java.util.Map.of());
        }
        PrinterStatus status;
        if (lower.contains("code=10001") || lower.contains("ready")
                || lower.contains("idle") || lower.contains("sleeping")) {
            status = PrinterStatus.IDLE;
        } else if (lower.contains("code=10002") || lower.contains("busy")
                || lower.contains("printing") || lower.contains("processing")) {
            status = PrinterStatus.BUSY;
        } else if (lower.contains("code=400")
                || lower.contains("toner") || lower.contains("paper")
                || lower.contains("jam") || lower.contains("cover")) {
            status = PrinterStatus.WARNING;
        } else if (lower.contains("offline") || lower.contains("unavailable")
                || lower.contains("maintenance")) {
            status = PrinterStatus.MAINTENANCE;
        } else {
            status = PrinterStatus.ONLINE;
        }
        return new DeviceStatus(status, reply.trim(), java.util.Map.of());
    }

    @Override
    public DeliveryResult deliver(DeviceSession session, RenderRequest request) {
        List<com.secureprint.drivers.format.RasterPage> pages = rasterizer.render(
                request.documentBytes(), request.mimeType(), request.documentName(),
                request.spec());
        byte[] pcl = new PclEncoder(dpi).encode(pages, request.spec());
        int sent = RawTcpTransport.send(session, pcl);
        return new DeliveryResult(request.jobId(), pages.size(), sent, pdlName());
    }

    protected String pdlName() {
        return "PCL5e";
    }

    @Override
    public void cancel(DeviceSession session, String deviceJobId) {
        // PCL raw sockets have no job-level cancel; a UEL reset drops anything still buffered on
        // the device, which is the best effort available for this transport.
        RawTcpTransport.send(session, "\u001B%-12345X@PJL RESET\r\n\u001B%-12345X"
                .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
    }
}
