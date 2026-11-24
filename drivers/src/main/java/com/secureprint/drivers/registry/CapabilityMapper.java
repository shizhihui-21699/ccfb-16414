package com.secureprint.drivers.registry;

import com.secureprint.core.domain.Capability;
import com.secureprint.core.domain.Printer;
import com.secureprint.drivers.spi.PrinterDriver;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

/**
 * Maps a driver's declared feature strings onto the core {@link Capability} enum, so the
 * release planner can reason about devices without depending on the drivers module.
 */
public final class CapabilityMapper {

    private CapabilityMapper() {
    }

    public static Set<Capability> fromDriver(PrinterDriver driver) {
        EnumSet<Capability> caps = EnumSet.noneOf(Capability.class);
        for (String feature : driver.supportedFeatures()) {
            switch (feature.toUpperCase(Locale.ROOT)) {
                case "MONO" -> caps.add(Capability.MONO);
                case "COLOR" -> caps.add(Capability.COLOR);
                case "DUPLEX" -> caps.add(Capability.DUPLEX);
                case "STAPLE" -> caps.add(Capability.STAPLE);
                case "A4" -> caps.add(Capability.A4);
                case "A3" -> caps.add(Capability.A3);
                case "LARGE_FORMAT" -> caps.add(Capability.LARGE_FORMAT);
                case "CARD_READER" -> caps.add(Capability.CARD_READER);
                case "QR_SCANNER" -> caps.add(Capability.QR_SCANNER);
                case "RELEASE_TERMINAL" -> caps.add(Capability.RELEASE_TERMINAL);
                default -> { /* unknown feature: ignore rather than fail discovery */ }
            }
        }
        return caps;
    }

    /**
     * Builds a {@link Printer} record for a discovered device. This is what discovery writes to
     * the inventory: the rest of the system then treats every brand identically.
     */
    public static Printer toPrinter(String printerId, String model, String siteId, String queue,
                                    String host, int port, PrinterDriver driver) {
        Set<Capability> caps = fromDriver(driver);
        return new Printer(printerId, model, driver.driverId(), siteId, queue, host, port, caps,
                com.secureprint.core.domain.PrinterStatus.OFFLINE);
    }
}
