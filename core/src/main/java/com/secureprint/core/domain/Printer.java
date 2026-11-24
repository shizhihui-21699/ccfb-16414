package com.secureprint.core.domain;

import java.util.EnumSet;
import java.util.Set;

/**
 * A physical device as seen by the release planner. The {@code driverId} is the only brand
 * knowledge the rest of the system needs: everything vendor-specific is resolved through
 * the driver registry.
 */
public record Printer(
        String printerId,
        String model,
        String driverId,
        String siteId,
        String queueName,
        String host,
        int port,
        Set<Capability> capabilities,
        PrinterStatus status) {

    public Printer {
        if (printerId == null || printerId.isBlank()) {
            throw new IllegalArgumentException("printerId required");
        }
        if (driverId == null || driverId.isBlank()) {
            throw new IllegalArgumentException("driverId required");
        }
        Set<Capability> c = capabilities == null ? Set.of() : capabilities;
        capabilities = c.isEmpty() ? Set.of() : Set.copyOf(EnumSet.copyOf(c));
    }

    public boolean supports(Capability c) {
        return capabilities.contains(c);
    }

    public boolean isReachable() {
        return status == PrinterStatus.ONLINE || status == PrinterStatus.IDLE;
    }
}
