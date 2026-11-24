package com.secureprint.agent.release;

/**
 * A printer as this agent knows it: enough to open a socket and pick a driver. Kept local so the
 * agent can print with the WAN down; the server's inventory is authoritative and is what
 * overwrites this on each sync.
 */
public record LocalPrinter(
        String printerId,
        String driverId,
        String host,
        int port,
        String queueName,
        boolean color,
        boolean duplex) {

    public LocalPrinter {
        if (printerId == null || driverId == null || host == null) {
            throw new IllegalArgumentException("printerId, driverId and host required");
        }
        if (port <= 0 || port > 65535) {
            port = 9100;
        }
    }

    public com.secureprint.drivers.spi.DeviceSession session(int timeoutMillis) {
        return new com.secureprint.drivers.spi.DeviceSession(printerId, host, port,
                timeoutMillis, queueName, null, null, null, false);
    }
}
