package com.secureprint.drivers.spi;

/**
 * Everything a driver needs to talk to one device. Credentials are opaque to the driver's
 * callers; drivers that need SNMP community strings or vendor web API tokens read them here.
 * Immutable so it can be cached per printer safely.
 */
public record DeviceSession(
        String printerId,
        String host,
        int port,
        int timeoutMillis,
        String queueName,
        String username,
        String password,
        String communityString,
        boolean tls) {

    public DeviceSession {
        if (printerId == null || host == null || host.isBlank()) {
            throw new IllegalArgumentException("printerId and host required");
        }
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException("port out of range");
        }
        if (timeoutMillis <= 0) {
            timeoutMillis = 5000;
        }
    }

    public DeviceSession withTimeout(int millis) {
        return new DeviceSession(printerId, host, port, millis, queueName, username, password,
                communityString, tls);
    }
}
