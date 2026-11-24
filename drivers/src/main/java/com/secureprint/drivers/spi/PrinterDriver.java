package com.secureprint.drivers.spi;

import com.secureprint.core.domain.PrinterStatus;

import java.util.Set;

/**
 * The single seam between the release system and a printer brand.
 *
 * <p>Every vendor (HP, Canon, Ricoh, Konica Minolta, Fuji Xerox, Brother, Epson, Zebra,
 * Lexmark, Kyocera, Sharp, Toshiba, Xerox, OKI, Samsung...) differs in transport (raw 9100,
 * IPP, LPD, vendor web API), page description language (PCL5, PCL6/PXL, PostScript, ESC/P,
 * ZPL, proprietary) and status reporting (SNMP, PJL, IPP attributes, vendor REST).
 *
 * <p>Rather than let that leak upward, the rest of the system knows only this interface. A
 * driver is a small, independently deployable adapter: adding a brand means adding one class
 * and one registry entry, never touching the release logic.
 *
 * <p><b>Design rule:</b> a driver never sees plaintext documents it was not asked to print, and
 * never sees the spool key. It receives a {@link RenderRequest} with already-unwrapped bytes and
 * a target {@link DeviceSession}. This keeps brand plugins outside the crypto trust boundary.
 */
public interface PrinterDriver {

    /** Stable identifier used in printer records and config, e.g. {@code hp.pcl6.raw9100}. */
    String driverId();

    /** Human-readable description for the admin console. */
    String description();

    /** Capabilities this driver+model combination can honour when rendering. */
    Set<String> supportedFeatures();

    /**
     * Probe the device. Must be cheap and must never throw for an unreachable printer: return
     * {@link PrinterStatus#OFFLINE} instead, so a flaky branch link cannot stall a release.
     */
    DeviceStatus probe(DeviceSession session);

    /**
     * Translate a neutral job into the device's page description language, delivering it to the
     * device. Implementations return only after the device has accepted the whole job.
     *
     * @throws DriverException on transport failure; the caller decides whether to retry
     * @throws UnsupportedJobException if the job asks for something this device cannot do
     */
    DeliveryResult deliver(DeviceSession session, RenderRequest request);

    /**
     * Best-effort cancellation of a job already accepted by the device (e.g. PJL job cancel).
     * Must not throw if the job already completed.
     */
    void cancel(DeviceSession session, String deviceJobId);
}
