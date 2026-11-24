package com.secureprint.agent.release;

import com.secureprint.agent.AgentConfig;
import com.secureprint.agent.store.OfflineSpool;
import com.secureprint.core.crypto.Ecies;
import com.secureprint.core.crypto.Ed25519;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.core.protocol.GrantSigning;
import com.secureprint.core.protocol.ReleaseGrant;
import com.secureprint.core.protocol.ReleaseManifest;
import com.secureprint.core.store.SpoolEnvelope;
import com.secureprint.core.util.Bytes;
import com.secureprint.drivers.spi.DeliveryResult;
import com.secureprint.drivers.spi.DeviceSession;
import com.secureprint.drivers.spi.PrinterDriver;
import com.secureprint.drivers.spi.RenderRequest;
import com.secureprint.drivers.registry.DriverRegistry;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enforces a release and drives the printer. This is the security boundary that matters most in
 * the offline case, because no server is watching: if this class is wrong, a stolen laptop with a
 * copied agent keystore prints other people's payslips.
 *
 * <p>Checks performed, in order, before a single byte goes to a printer:
 * <ol>
 *   <li>Grant signature verifies under the pinned server key.</li>
 *   <li>Grant is addressed to this agent and this printer.</li>
 *   <li>Grant is inside its validity window.</li>
 *   <li>Grant's issuing employee matches the badge that is actually at the device (the caller
 *       passes both; they must agree).</li>
 *   <li>The grant's nonce has never been used on this agent (single use, even across restart,
 *       via the persisted used-nonce set).</li>
 *   <li>The data key unwraps under this agent's private key with AAD binding (agent, job,
 *       employee).</li>
 *   <li>For offline grants: the job is in the current, unexpired manifest and still inside its
 *       hold deadline.</li>
 * </ol>
 *
 * <p>Only then is the document decrypted, rendered by the brand driver, delivered, and the
 * plaintext zeroed. The grant and nonce are consumed <em>before</em> delivery: a device failure
 * after that point means the employee must request a new grant, never that a captured grant can
 * be replayed.
 */
public final class ReleaseEngine {

    private final AgentConfig config;
    private final OfflineSpool spool;
    private final DriverRegistry drivers;
    private final Clock clock;
    private final Map<String, LocalPrinter> printers;
    private final NonceStore nonces;
    private final com.secureprint.agent.sync.OfflineJournal journal;

    public ReleaseEngine(AgentConfig config, OfflineSpool spool, DriverRegistry drivers,
                         Clock clock, Map<String, LocalPrinter> printers) {
        this(config, spool, drivers, clock, printers, null, null);
    }

    public ReleaseEngine(AgentConfig config, OfflineSpool spool, DriverRegistry drivers,
                         Clock clock, Map<String, LocalPrinter> printers,
                         com.secureprint.agent.sync.OfflineJournal journal) {
        this(config, spool, drivers, clock, printers, journal, null);
    }

    /**
     * @param nonces durable nonce store; when null an in-memory store is used, which makes
     *               single-use hold only for the life of the process. Production must pass one.
     */
    public ReleaseEngine(AgentConfig config, OfflineSpool spool, DriverRegistry drivers,
                         Clock clock, Map<String, LocalPrinter> printers,
                         com.secureprint.agent.sync.OfflineJournal journal, NonceStore nonces) {
        this.config = config;
        this.spool = spool;
        this.drivers = drivers;
        this.clock = clock;
        this.printers = Map.copyOf(printers);
        this.journal = journal;
        this.nonces = nonces != null ? nonces : new NonceStore(
                java.nio.file.Path.of(System.getProperty("java.io.tmpdir"),
                        "secure-print-nonces-" + ProcessHandle.current().pid() + ".tsv"),
                java.time.Duration.ofHours(24));
    }

    public sealed interface Outcome permits Outcome.Delivered, Outcome.Refused {
        record Delivered(String jobId, DeliveryResult delivery) implements Outcome {
        }

        record Refused(String reason) implements Outcome {
        }
    }

    /** Authenticated badge tap context: who the device says is standing there. */
    public record Tap(String employeeId, String printerId) {
    }

    public Outcome releaseOffline(String grantJson, String signatureB64, Tap tap) {
        ReleaseGrant grant;
        try {
            grant = com.secureprint.core.util.Json.fromJson(grantJson, ReleaseGrant.class);
        } catch (RuntimeException e) {
            return new Outcome.Refused("malformed grant");
        }
        byte[] signature;
        try {
            signature = Bytes.unb64url(signatureB64);
        } catch (RuntimeException e) {
            return new Outcome.Refused("malformed signature");
        }

        if (!Ed25519.verify(Ed25519.decodePublic(config.serverPublicKeyEncoded()),
                GrantSigning.canonicalGrant(grant), signature)) {
            return new Outcome.Refused("grant signature invalid");
        }
        if (!config.agentId().equals(grant.agentId())) {
            return new Outcome.Refused("grant addressed to another agent");
        }
        if (!tap.printerId().equals(grant.printerId())) {
            return new Outcome.Refused("grant is for a different printer");
        }
        if (!tap.employeeId().equals(grant.employeeId())) {
            return new Outcome.Refused("grant does not match the authenticated badge");
        }
        Instant now = clock.instant();
        Instant skewedNow = now.plus(config.grantClockSkew());
        if (now.isBefore(grant.notBefore())) {
            return new Outcome.Refused("grant not yet valid");
        }
        if (!skewedNow.isBefore(grant.expiresAt())) {
            return new Outcome.Refused("grant expired");
        }
        if (!nonces.consume(grant.nonce())) {
            return new Outcome.Refused("grant already used");
        }
        if (grant.mode() == ReleaseGrant.Mode.OFFLINE) {
            String manifestProblem = checkManifestAuthority(grant, now);
            if (manifestProblem != null) {
                return new Outcome.Refused(manifestProblem);
            }
        }

        // Record the attempt BEFORE printing. If this box dies mid-delivery, the journal still
        // holds an UNKNOWN entry so reconciliation can tell the truth about an ambiguous print.
        boolean journaled = false;
        if (journal != null && grant.mode() == ReleaseGrant.Mode.OFFLINE) {
            journaled = journal.appendAttempt(new com.secureprint.agent.sync.OfflineJournal.Entry(
                    grant.jobId(), tap.employeeId(), tap.printerId(), grant.grantId(),
                    clock.instant(), "IN_PROGRESS", "offline release started"));
        }

        byte[] plaintext = null;
        try {
            SpoolEnvelope.Opened opened = openJob(grant, tap.employeeId());
            plaintext = opened.documentBytes();
            Outcome outcome = deliver(grant, opened.spec(), plaintext);
            if (journaled) {
                journal.updateOutcome(grant.jobId(), "DELIVERED", "device accepted job");
            }
            return outcome;
        } catch (Refusal r) {
            if (journaled) {
                journal.updateOutcome(grant.jobId(), "FAILED", r.getMessage());
            }
            return new Outcome.Refused(r.getMessage());
        } catch (RuntimeException e) {
            if (journaled) {
                journal.updateOutcome(grant.jobId(), "FAILED", "delivery error: "
                        + e.getClass().getSimpleName());
            }
            throw e;
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
            // A grant is single-use regardless of what happened after nonce consumption.
        }
    }

    /** Returns null when the manifest still authorizes this job, else a refusal reason. */
    private String checkManifestAuthority(ReleaseGrant grant, Instant now) {
        ReleaseManifest manifest = spool.currentManifest().orElse(null);
        if (manifest == null) {
            return "no offline manifest installed";
        }
        if (!manifest.isUsableAt(now)) {
            return "offline manifest expired; connect to the server";
        }
        ReleaseManifest.Entry entry = manifest.entry(grant.jobId());
        if (entry == null) {
            return "job not in the current offline manifest";
        }
        if (!entry.employeeId().equals(grant.employeeId())) {
            return "offline manifest entry belongs to another employee";
        }
        if (!now.isBefore(entry.holdUntil())) {
            return "job hold window elapsed";
        }
        return null;
    }

    private SpoolEnvelope.Opened openJob(ReleaseGrant grant, String employeeId) {
        byte[] dataKey = Ecies.open(
                Ecies.decodePrivate(config.agentPrivateKeyEncoded()),
                Ecies.decodePublic(config.agentPublicKeyEncoded()),
                Bytes.unb64url(grant.jobDataKeyWrapped()),
                SpoolEnvelope.agentKeyAad(config.agentId(), grant.jobId(), employeeId));
        try {
            byte[] packed = spool.rawSpoolFor(grant.jobId())
                    .orElseThrow(() -> new Refusal("spool blob not present on this agent"));
            SpoolEnvelope.Sealed sealed = SpoolEnvelope.unpack(packed);
            return SpoolEnvelope.openWithDataKey(dataKey, grant.jobId(), employeeId,
                    sealed.ciphertext());
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
    }

    private Outcome deliver(ReleaseGrant grant, PrintSpec spec, byte[] plaintext) {
        LocalPrinter printer = printers.get(grant.printerId());
        if (printer == null) {
            throw new Refusal("printer " + grant.printerId() + " not configured on this agent");
        }
        PrinterDriver driver = drivers.byId(printer.driverId())
                .orElseThrow(() -> new Refusal("driver " + printer.driverId()
                        + " not available on this agent"));
        DeviceSession session = printer.session(config.connectTimeoutMillis());
        RenderRequest request = new RenderRequest(grant.jobId(), spec.documentName(),
                spec.mimeType(), plaintext, spec, grant.grantId(), grant.employeeId());
        DeliveryResult result = driver.deliver(session, request);
        if (grant.mode() == ReleaseGrant.Mode.OFFLINE) {
            spool.touchReleased(grant.jobId());
        }
        return new Outcome.Delivered(grant.jobId(), result);
    }

    public int usedNonceCount() {
        return nonces.size();
    }

    static final class Refusal extends RuntimeException {
        Refusal(String message) {
            super(message);
        }
    }
}
