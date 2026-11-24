package com.secureprint.server.service;

import com.secureprint.core.crypto.Ecies;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of branch release agents.
 *
 * <p>Each agent is enrolled once by an administrator who copies its public key (X25519) from the
 * agent's local keystore. The server never sees an agent's private key, which is exactly what
 * lets an agent keep working while the WAN is down: the server can pre-wrap job keys to it at any
 * time, but cannot decrypt anything on its behalf.
 *
 * <p>{@code lastSeen} and {@code lastSequence} drive two operational checks: stale agents are
 * flagged in the admin console, and the server tracks the highest manifest sequence it issued
 * per agent so a rollback of server state cannot silently lower it.
 */
public final class AgentRegistry {

    public record Agent(
            String agentId,
            String siteId,
            String publicKeyEncoded,
            String fingerprint,
            Instant enrolledAt,
            Instant lastSeen,
            long lastSequence,
            boolean enabled) {

        public Agent withSeen(Instant when) {
            return new Agent(agentId, siteId, publicKeyEncoded, fingerprint, enrolledAt, when,
                    lastSequence, enabled);
        }

        public Agent withSequence(long sequence, Instant when) {
            return new Agent(agentId, siteId, publicKeyEncoded, fingerprint, enrolledAt, when,
                    sequence, enabled);
        }

        public Agent disabled() {
            return new Agent(agentId, siteId, publicKeyEncoded, fingerprint, enrolledAt, lastSeen,
                    lastSequence, false);
        }

        public java.security.PublicKey publicKey() {
            return Ecies.decodePublic(publicKeyEncoded);
        }
    }

    private final Map<String, Agent> agents = new ConcurrentHashMap<>();

    public Agent enroll(String agentId, String siteId, String publicKeyEncoded, Instant now) {
        if (agents.containsKey(agentId)) {
            throw new IllegalStateException("agent already enrolled: " + agentId);
        }
        var pub = Ecies.decodePublic(publicKeyEncoded);
        Agent agent = new Agent(agentId, siteId, publicKeyEncoded, Ecies.fingerprint(pub), now,
                now, 0, true);
        agents.put(agentId, agent);
        return agent;
    }

    public Optional<Agent> agent(String agentId) {
        return Optional.ofNullable(agents.get(agentId));
    }

    /** All enabled agents that serve a site. Most sites have one; large ones may have a pair. */
    public List<Agent> agentsForSite(String siteId) {
        return agents.values().stream()
                .filter(a -> a.enabled() && siteId.equals(a.siteId()))
                .sorted(java.util.Comparator.comparing(Agent::agentId))
                .toList();
    }

    public List<Agent> all() {
        return agents.values().stream()
                .sorted(java.util.Comparator.comparing(Agent::agentId))
                .toList();
    }

    public synchronized Agent recordSeen(String agentId, long sequence, Instant when) {
        Agent current = agents.get(agentId);
        if (current == null) {
            throw new IllegalStateException("unknown agent " + agentId);
        }
        Agent updated = sequence > current.lastSequence()
                ? current.withSequence(sequence, when)
                : current.withSeen(when);
        agents.put(agentId, updated);
        return updated;
    }

    public synchronized void setEnabled(String agentId, boolean enabled) {
        Agent current = agents.get(agentId);
        if (current == null) {
            throw new IllegalStateException("unknown agent " + agentId);
        }
        agents.put(agentId, enabled ? current : current.disabled());
    }

    /**
     * Agents serving a site whose last contact is older than {@code staleAfter}. Used by the
     * admin console and by the offline-manifest sweeper to decide whether pre-wrapping is still
     * worthwhile.
     */
    public List<Agent> staleAgents(Instant now, java.time.Duration staleAfter) {
        Instant cutoff = now.minus(staleAfter);
        return agents.values().stream()
                .filter(a -> a.enabled() && (a.lastSeen() == null || a.lastSeen().isBefore(cutoff)))
                .sorted(java.util.Comparator.comparing(Agent::agentId))
                .toList();
    }
}
