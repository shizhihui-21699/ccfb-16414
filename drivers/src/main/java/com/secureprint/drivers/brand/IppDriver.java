package com.secureprint.drivers.brand;

import com.secureprint.core.domain.PrintSpec;
import com.secureprint.drivers.spi.DeliveryResult;
import com.secureprint.drivers.spi.DeviceSession;
import com.secureprint.drivers.spi.DeviceStatus;
import com.secureprint.drivers.spi.PrinterDriver;
import com.secureprint.drivers.spi.RenderRequest;
import com.secureprint.drivers.transport.IppTransport;

import java.util.Set;

/**
 * IPP/CUPS driver — used for fleet printers whose vendor exposes IPP (modern MFPs, AirPrint, and
 * everything fronted by CUPS). IPP is preferred when available because the device returns a real
 * per-job id and a per-job terminal state, which lets the agent confirm a release instead of
 * assuming success from a TCP write.
 *
 * <p>Works for any brand that speaks IPP; per-brand subclasses only pre-select capability flags
 * and document-format preferences.
 */
public class IppDriver implements PrinterDriver {

    private final String driverId;
    private final String description;
    private final Set<String> features;
    private final IppTransport transport = new IppTransport("secure-print");

    public IppDriver(String driverId, String description, Set<String> features) {
        this.driverId = driverId;
        this.description = description;
        this.features = Set.copyOf(features);
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
    public DeviceStatus probe(DeviceSession session) {
        try {
            // Print-Job a zero-length document would be rude; a Get-Job-Attributes probe on a
            // non-existent job tests reachability without producing paper, and a device that
            // speaks IPP answers with a well-formed error.
            String state = transport.jobState(session, -1);
            return new DeviceStatus(
                    "unknown".equals(state)
                            ? com.secureprint.core.domain.PrinterStatus.ONLINE
                            : com.secureprint.core.domain.PrinterStatus.IDLE,
                    "IPP reachable, probe state=" + state, java.util.Map.of());
        } catch (RuntimeException e) {
            return DeviceStatus.offline(e.getMessage());
        }
    }

    @Override
    public DeliveryResult deliver(DeviceSession session, RenderRequest request) {
        IppTransport.PrintResult result =
                transport.printJob(session, request.documentBytes(), request.spec());
        if (!result.accepted()) {
            throw new com.secureprint.drivers.spi.DriverException(driverId(),
                    "IPP rejected job: " + result.statusText(), false);
        }
        return new DeliveryResult(Integer.toString(result.jobId()), pageEstimate(request.spec()),
                request.documentBytes().length, "IPP");
    }

    private static int pageEstimate(PrintSpec spec) {
        return spec.pages().isEmpty() ? 1 : spec.pages().size();
    }

    @Override
    public void cancel(DeviceSession session, String deviceJobId) {
        try {
            int jobId = Integer.parseInt(deviceJobId);
            transport.cancelJob(session, jobId);
        } catch (NumberFormatException ignored) {
            // Nothing sensible to cancel if we never got a device job id.
        }
    }
}
