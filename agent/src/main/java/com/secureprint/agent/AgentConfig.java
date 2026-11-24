package com.secureprint.agent;

import java.time.Duration;

/**
 * Agent configuration. An agent is a small, site-local appliance (a PC in the print room or a
 * hardened mini-PC) that owns the network paths to the printers at that site and holds a local
 * encrypted spool so badge taps keep working when the WAN does.
 */
public record AgentConfig(
        String agentId,
        String siteId,
        String serverPublicKeyEncoded,
        String agentPublicKeyEncoded,
        String agentPrivateKeyEncoded,
        Duration manifestMaxAge,
        Duration grantClockSkew,
        int connectTimeoutMillis,
        int maxOfflineQueue) {

    public AgentConfig {
        if (agentId == null || agentId.isBlank()) {
            throw new IllegalArgumentException("agentId required");
        }
        if (siteId == null || siteId.isBlank()) {
            throw new IllegalArgumentException("siteId required");
        }
        if (serverPublicKeyEncoded == null || agentPrivateKeyEncoded == null) {
            throw new IllegalArgumentException("keys required");
        }
        if (maxOfflineQueue <= 0) {
            maxOfflineQueue = 1000;
        }
    }
}
