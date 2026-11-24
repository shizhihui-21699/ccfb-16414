package com.secureprint.drivers.spi;

/** The device is reachable but cannot satisfy the job (no colour, no A3 tray, no staple unit). */
public class UnsupportedJobException extends DriverException {

    public UnsupportedJobException(String driverId, String message) {
        super(driverId, message, true);
    }
}
