package com.secureprint.drivers.spi;

import com.secureprint.core.domain.PrinterStatus;

import java.util.Map;

/** Result of a device probe. Timestamped so callers can judge staleness without a clock. */
public record DeviceStatus(
        PrinterStatus status,
        String detail,
        Map<String, String> attributes) {

    public DeviceStatus {
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }

    public static DeviceStatus offline(String reason) {
        return new DeviceStatus(PrinterStatus.OFFLINE, reason, Map.of());
    }

    public boolean isReady() {
        return status == PrinterStatus.ONLINE || status == PrinterStatus.IDLE;
    }
}
