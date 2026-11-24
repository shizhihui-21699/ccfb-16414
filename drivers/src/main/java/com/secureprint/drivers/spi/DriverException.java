package com.secureprint.drivers.spi;

/** Transport or protocol failure talking to a device. Safe to retry unless {@link #permanent}. */
public class DriverException extends RuntimeException {

    private final boolean permanent;
    private final String driverId;

    public DriverException(String driverId, String message, boolean permanent) {
        super(message);
        this.driverId = driverId;
        this.permanent = permanent;
    }

    public DriverException(String driverId, String message, boolean permanent, Throwable cause) {
        super(message, cause);
        this.driverId = driverId;
        this.permanent = permanent;
    }

    public boolean permanent() {
        return permanent;
    }

    public String driverId() {
        return driverId;
    }
}
