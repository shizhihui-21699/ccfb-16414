package com.secureprint.server;

import com.secureprint.core.domain.JobState;
import com.secureprint.core.protocol.ReleaseManifest;
import com.secureprint.core.util.Json;
import com.secureprint.server.service.ManifestService;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManifestServiceTest extends ServerTestBase {

    private ManifestService manifests() {
        return new ManifestService(store, spool, envelope, agents, config, clock);
    }

    @Test
    void manifestListsOnlyHeldJobsForTheAgentSite() {
        employee("emp-sh", "AAAA0001", SITE_SH);
        employee("emp-muc", "BBBB0002", SITE_MUC);
        agent("agent-sh", SITE_SH);
        submit("emp-sh", "shanghai doc");
        submit("emp-muc", "munich doc");

        var bundle = manifests().buildForAgent("agent-sh").orElseThrow();
        ReleaseManifest m = bundle.manifest();
        assertEquals("agent-sh", m.agentId());
        assertEquals(SITE_SH, m.siteId());
        assertEquals(1, m.entries().size());
        assertEquals("emp-sh", m.entries().get(0).employeeId());
        assertEquals(1, bundle.blobs().size());
    }

    @Test
    void manifestExcludesExpiredJobs() {
        employee("emp-sh", "AAAA0001", SITE_SH);
        agent("agent-sh", SITE_SH);
        submit("emp-sh", "short", Duration.ofMinutes(10));

        moveClockTo(NOW.plus(Duration.ofHours(1)));
        var bundle = manifests().buildForAgent("agent-sh").orElseThrow();
        assertEquals(0, bundle.manifest().entries().size());
    }

    @Test
    void manifestExcludesReleasedAndCancelledJobs() {
        employee("emp-sh", "AAAA0001", SITE_SH);
        agent("agent-sh", SITE_SH);
        String cancelled = submit("emp-sh", "cancel me");
        releases.cancel(jobId(cancelled), "emp-sh");

        var bundle = manifests().buildForAgent("agent-sh").orElseThrow();
        assertEquals(0, bundle.manifest().entries().size());
    }

    @Test
    void sequenceAdvancesPerAgentAndIsNotShared() {
        employee("emp-sh", "AAAA0001", SITE_SH);
        employee("emp-muc", "BBBB0002", SITE_MUC);
        agent("agent-sh", SITE_SH);
        agent("agent-muc", SITE_MUC);
        submit("emp-sh", "x");

        ManifestService m = manifests();
        var first = m.buildForAgent("agent-sh").orElseThrow().manifest();
        long firstSeq = first.sequence();
        m.acknowledge("agent-sh", firstSeq);
        var second = m.buildForAgent("agent-sh").orElseThrow().manifest();
        assertEquals(firstSeq + 1, second.sequence());

        var muc = m.buildForAgent("agent-muc").orElseThrow().manifest();
        assertEquals(1, muc.sequence(), "other agent's sequence is independent");
    }

    @Test
    void unknownAgentGetsNoManifest() {
        assertTrue(manifests().buildForAgent("agent-ghost").isEmpty());
    }

    @Test
    void manifestIsSignedAndJsonRoundTrips() {
        employee("emp-sh", "AAAA0001", SITE_SH);
        agent("agent-sh", SITE_SH);
        submit("emp-sh", "x");

        var bundle = manifests().buildForAgent("agent-sh").orElseThrow();
        String json = Json.toJson(bundle.manifest());
        ReleaseManifest parsed = Json.fromJson(json, ReleaseManifest.class);
        assertEquals(bundle.manifest().manifestId(), parsed.manifestId());
        assertEquals(bundle.manifest().entries().size(), parsed.entries().size());
        assertNotNull(bundle.signatureB64());
        assertFalse(bundle.signatureB64().isBlank());
    }

    @Test
    void manifestIncludesWrappedKeyPerEntrySoAgentCanDecrypt() {
        employee("emp-sh", "AAAA0001", SITE_SH);
        agent("agent-sh", SITE_SH);
        submit("emp-sh", "decryptable");

        var bundle = manifests().buildForAgent("agent-sh").orElseThrow();
        ReleaseManifest.Entry entry = bundle.manifest().entries().get(0);
        assertFalse(entry.jobDataKeyWrapped().isBlank(),
                "agent needs a wrapped data key to print offline");
        assertTrue(entry.holdUntil().isAfter(NOW));
    }

    @Test
    void blobsAlignWithEntries() {
        employee("emp-sh", "AAAA0001", SITE_SH);
        agent("agent-sh", SITE_SH);
        for (int i = 0; i < 3; i++) {
            submit("emp-sh", "doc " + i);
        }
        var bundle = manifests().buildForAgent("agent-sh").orElseThrow();
        Map<String, byte[]> byId = new HashMap<>();
        for (var blob : bundle.blobs()) {
            byId.put(blob.objectId(), blob.packed());
        }
        assertEquals(3, byId.size());
        for (ReleaseManifest.Entry e : bundle.manifest().entries()) {
            assertTrue(byId.containsKey(e.spoolObjectId()),
                    "every manifest entry must ship its blob");
        }
    }
}
