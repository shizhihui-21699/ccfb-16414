package com.secureprint.drivers.brand;

import com.secureprint.core.domain.PrinterStatus;
import com.secureprint.drivers.spi.DeviceStatus;

import java.util.Locale;
import java.util.Map;

/**
 * Kyocera ECOSYS / TASKalfa over PCL5 on raw 9100.
 *
 * <p>Kyocera's PJL adds its own status vocabulary ("Sleeping", "Warming up", "Toner Low",
 * "Waste Toner Box Full") and reports paper-jam states via {@code CODE=40xxx}. Its command set
 * (KPDL) is a PostScript clone, but PCL5 raster is more reliable across the model range, so we
 * stay on PCL and only widen the status keyword map here.
 */
public final class KyoceraDriver extends PclRawSocketDriver {

    public KyoceraDriver() {
        super(600);
    }

    @Override
    public String driverId() {
        return "kyocera.ecosys.pcl5.raw9100";
    }

    @Override
    public String description() {
        return "Kyocera ECOSYS / TASKalfa (PCL5 raster over raw TCP 9100)";
    }

    @Override
    protected DeviceStatus interpret(String reply) {
        String lower = reply == null ? "" : reply.toLowerCase(Locale.ROOT);
        if (lower.contains("warming") || lower.contains("sleeping")
                || lower.contains("recover")) {
            return new DeviceStatus(PrinterStatus.WARNING, reply.trim(), Map.of());
        }
        if (lower.contains("waste toner") || lower.contains("toner low")
                || lower.contains("maintenance")) {
            return new DeviceStatus(PrinterStatus.WARNING, reply.trim(), Map.of());
        }
        return super.interpret(reply);
    }
}
