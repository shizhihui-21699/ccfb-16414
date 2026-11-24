package com.secureprint.core.protocol;

import com.secureprint.core.crypto.Ed25519;
import com.secureprint.core.util.Bytes;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManifestVerifierTest {

    private static final Instant NOW = Instant.parse("2026-11-25T10:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private final KeyPair server = Ed25519.generate();

    private ReleaseManifest manifest(long seq, Instant issued, Instant expires, String agent) {
        return new ReleaseManifest("man-" + seq, agent, "site-shanghai", seq, issued,
                issued.minusSeconds(5), expires, List.of(
                new ReleaseManifest.Entry("job-1", "emp-1", "payslip.pdf",
                        NOW.plus(Duration.ofHours(4)), "obj-1", "d2tnZWQ=", false)));
    }

    @Test
    void acceptsFreshSignedManifest() {
        ManifestVerifier v = new ManifestVerifier(server.getPublic(), CLOCK,
                Duration.ofHours(24));
        ReleaseManifest m = manifest(1, NOW.minusSeconds(60), NOW.plusSeconds(3600), "agent-1");
        byte[] sig = ManifestVerifier.sign(server.getPrivate(), m);
        assertInstanceOf(ManifestVerifier.Result.Accepted.class, v.verify(m, sig, "agent-1"));
    }

    @Test
    void rejectsTamperedEntry() {
        ManifestVerifier v = new ManifestVerifier(server.getPublic(), CLOCK,
                Duration.ofHours(24));
        ReleaseManifest m = manifest(1, NOW.minusSeconds(60), NOW.plusSeconds(3600), "agent-1");
        byte[] sig = ManifestVerifier.sign(server.getPrivate(), m);
        ReleaseManifest tampered = new ReleaseManifest(m.manifestId(), m.agentId(), m.siteId(),
                m.sequence(), m.issuedAt(), m.notBefore(), m.expiresAt(), List.of(
                new ReleaseManifest.Entry("job-1", "emp-2", "payslip.pdf",
                        NOW.plus(Duration.ofHours(4)), "obj-1", "d2tnZWQ=", false)));
        assertInstanceOf(ManifestVerifier.Result.Rejected.class,
                v.verify(tampered, sig, "agent-1"));
    }

    @Test
    void rejectsReplayOfOlderSequence() {
        ManifestVerifier v = new ManifestVerifier(server.getPublic(), CLOCK,
                Duration.ofHours(24));
        ReleaseManifest newer = manifest(5, NOW.minusSeconds(60), NOW.plusSeconds(3600), "agent-1");
        v.verify(newer, ManifestVerifier.sign(server.getPrivate(), newer), "agent-1");

        ReleaseManifest older = manifest(4, NOW.minusSeconds(60), NOW.plusSeconds(3600), "agent-1");
        assertInstanceOf(ManifestVerifier.Result.Rejected.class,
                v.verify(older, ManifestVerifier.sign(server.getPrivate(), older), "agent-1"));
    }

    @Test
    void rejectsExpiredAndTooOld() {
        ManifestVerifier v = new ManifestVerifier(server.getPublic(), CLOCK,
                Duration.ofHours(2));
        ReleaseManifest expired = manifest(1, NOW.minusSeconds(7200), NOW.minusSeconds(60),
                "agent-1");
        assertInstanceOf(ManifestVerifier.Result.Rejected.class,
                v.verify(expired, ManifestVerifier.sign(server.getPrivate(), expired), "agent-1"));

        ManifestVerifier v2 = new ManifestVerifier(server.getPublic(), CLOCK, Duration.ofHours(2));
        ReleaseManifest stale = manifest(1, NOW.minus(Duration.ofHours(5)),
                NOW.plusSeconds(3600), "agent-1");
        assertInstanceOf(ManifestVerifier.Result.Rejected.class,
                v2.verify(stale, ManifestVerifier.sign(server.getPrivate(), stale), "agent-1"));
    }

    @Test
    void rejectsWrongAgentAndDuplicates() {
        ManifestVerifier v = new ManifestVerifier(server.getPublic(), CLOCK,
                Duration.ofHours(24));
        ReleaseManifest m = manifest(1, NOW.minusSeconds(60), NOW.plusSeconds(3600), "agent-1");
        byte[] sig = ManifestVerifier.sign(server.getPrivate(), m);
        assertInstanceOf(ManifestVerifier.Result.Rejected.class, v.verify(m, sig, "agent-2"));

        ReleaseManifest dup = new ReleaseManifest("man", "agent-1", "site", 1,
                NOW.minusSeconds(60), NOW.minusSeconds(65), NOW.plusSeconds(3600), List.of(
                new ReleaseManifest.Entry("job-1", "emp-1", "a.pdf", NOW.plusSeconds(9),
                        "obj-1", "k", false),
                new ReleaseManifest.Entry("job-1", "emp-1", "a.pdf", NOW.plusSeconds(9),
                        "obj-1", "k", false)));
        assertInstanceOf(ManifestVerifier.Result.Rejected.class,
                v.verify(dup, ManifestVerifier.sign(server.getPrivate(), dup), "agent-1"));
    }

    @Test
    void restoreSequenceBlocksOldManifestAfterRestart() {
        ManifestVerifier v = new ManifestVerifier(server.getPublic(), CLOCK,
                Duration.ofHours(24));
        v.restoreSequence(10);
        ReleaseManifest m = manifest(10, NOW.minusSeconds(60), NOW.plusSeconds(3600), "agent-1");
        assertTrue(v.verify(m, ManifestVerifier.sign(server.getPrivate(), m), "agent-1")
                instanceof ManifestVerifier.Result.Rejected);
    }

    @Test
    void signatureOverDifferentKeyRejected() {
        KeyPair rogue = Ed25519.generate();
        ManifestVerifier v = new ManifestVerifier(server.getPublic(), CLOCK,
                Duration.ofHours(24));
        ReleaseManifest m = manifest(1, NOW.minusSeconds(60), NOW.plusSeconds(3600), "agent-1");
        assertTrue(v.verify(m, ManifestVerifier.sign(rogue.getPrivate(), m), "agent-1")
                instanceof ManifestVerifier.Result.Rejected);
    }

    @Test
    void canonicalFormIsOrderIndependent() {
        ReleaseManifest.Entry a = new ReleaseManifest.Entry("job-b", "e", "x", NOW.plusSeconds(9), "o", "k", false);
        ReleaseManifest.Entry b = new ReleaseManifest.Entry("job-a", "e", "x", NOW.plusSeconds(9), "o", "k", false);
        ReleaseManifest m1 = new ReleaseManifest("m", "a", "s", 1, NOW, NOW.minusSeconds(1),
                NOW.plusSeconds(100), List.of(a, b));
        ReleaseManifest m2 = new ReleaseManifest("m", "a", "s", 1, NOW, NOW.minusSeconds(1),
                NOW.plusSeconds(100), List.of(b, a));
        byte[] c1 = GrantSigning.canonicalManifest(m1);
        byte[] c2 = GrantSigning.canonicalManifest(m2);
        assertTrue(Bytes.constantTimeEquals(c1, c2));
    }
}
