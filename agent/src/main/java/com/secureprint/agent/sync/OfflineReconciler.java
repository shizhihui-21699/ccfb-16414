package com.secureprint.agent.sync;

import java.util.ArrayList;
import java.util.List;

/**
 * Drains the offline journal to the server once the WAN is back.
 *
 * <p>This is the other half of offline release. The agent does not just "forget" what it printed:
 * it replays each journaled attempt and records the server's verdict. The verdicts that are not
 * plain confirmations (double print, printed-after-cancel, printed-after-expiry) are surfaced,
 * because those are exactly the events a compliance review needs to see.
 *
 * <p>Transport is injected so the same reconciler works over HTTP, a message queue, or a
 * sneakernet USB exchange (some sites really do reconcile weekly by USB).
 */
public final class OfflineReconciler {

    /** Server-side view of one attempt. Mirrors the HTTP contract, not the server class. */
    public interface ServerGateway {
        Result reconcile(String agentId, String jobId, boolean delivered, String detail);
    }

    public record Result(String verdict, String detail) {
    }

    public record Summary(int sent, int confirmed, int incidents, int failed) {
    }

    private final String agentId;
    private final OfflineJournal journal;
    private final ServerGateway gateway;

    public OfflineReconciler(String agentId, OfflineJournal journal, ServerGateway gateway) {
        this.agentId = agentId;
        this.journal = journal;
        this.gateway = gateway;
    }

    public Summary replay() {
        List<OfflineJournal.Entry> pending = journal.pending();
        if (pending.isEmpty()) {
            return new Summary(0, 0, 0, 0);
        }
        List<String> acknowledged = new ArrayList<>();
        int confirmed = 0;
        int incidents = 0;
        int failed = 0;
        for (OfflineJournal.Entry entry : pending) {
            if ("IN_PROGRESS".equals(entry.outcome())) {
                // The agent died mid-delivery. We cannot know whether paper came out. Report it
                // as an incident rather than assuming either way, and let a human reconcile it.
                Result r = gateway.reconcile(agentId, entry.jobId(), true,
                        "outcome unknown: agent restarted during delivery");
                incidents++;
                acknowledged.add(entry.jobId());
                continue;
            }
            boolean delivered = "DELIVERED".equals(entry.outcome());
            Result r = gateway.reconcile(agentId, entry.jobId(), delivered, entry.detail());
            switch (r.verdict()) {
                case "CONFIRMED" -> confirmed++;
                case "REVERTED_TO_HELD" -> {
                    // nothing to count separately; the job is simply available again
                }
                case "ALREADY_RELEASED_DOUBLE_PRINT", "PRINTED_AFTER_CANCEL",
                     "PRINTED_AFTER_EXPIRY" -> incidents++;
                default -> failed++;
            }
            acknowledged.add(entry.jobId());
        }
        journal.acknowledge(acknowledged);
        return new Summary(pending.size(), confirmed, incidents, failed);
    }
}
