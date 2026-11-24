package com.secureprint.server.service;

import com.secureprint.core.domain.ColorMode;
import com.secureprint.core.domain.DuplexMode;
import com.secureprint.core.domain.JobState;
import com.secureprint.core.domain.PaperSize;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.core.domain.Employee;
import com.secureprint.core.store.SpoolEnvelope;
import com.secureprint.core.store.SpoolStore;
import com.secureprint.core.util.Bytes;
import com.secureprint.server.config.ServerConfig;
import com.secureprint.server.security.ReleaseTokenService;
import com.secureprint.server.store.JobStore;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Accepts a document from an employee and puts it into a held, encrypted state.
 *
 * <p>The invariant this class protects: <b>document bytes exist in plaintext only inside this
 * method's stack frame</b>. They are sealed with a job-specific key before touching the store,
 * and the caller-provided byte array is zeroed after upload so a heap dump of the request thread
 * cannot recover a payslip.
 */
public final class SubmissionService {

    private final JobStore store;
    private final SpoolStore spool;
    private final SpoolEnvelope envelope;
    private final ReleaseTokenService tokens;
    private final ServerConfig config;
    private final Clock clock;

    public SubmissionService(JobStore store, SpoolStore spool, SpoolEnvelope envelope,
                             ReleaseTokenService tokens, ServerConfig config, Clock clock) {
        this.store = store;
        this.spool = spool;
        this.envelope = envelope;
        this.tokens = tokens;
        this.config = config;
        this.clock = clock;
    }

    /** What the client needs back: the job id and its one-time release token. */
    public record Submitted(String jobId, String releaseToken, Instant holdUntil) {
    }

    public record SubmitRequest(
            String employeeId,
            String documentName,
            String mimeType,
            byte[] documentBytes,
            int copies,
            ColorMode colorMode,
            DuplexMode duplex,
            PaperSize paperSize,
            List<Integer> pages,
            String documentClass,
            Duration holdTtl) {
    }

    public Submitted submit(SubmitRequest request) {
        Employee employee = store.employee(request.employeeId())
                .orElseThrow(() -> new SubmissionRejected("unknown employee"));
        if (!employee.active()) {
            throw new SubmissionRejected("employee is not active");
        }
        if (request.documentBytes() == null || request.documentBytes().length == 0) {
            throw new SubmissionRejected("empty document");
        }
        if (request.documentBytes().length > config.maxDocumentBytes()) {
            throw new SubmissionRejected("document exceeds " + config.maxDocumentBytes() + " bytes");
        }

        Instant now = clock.instant();
        Duration ttl = request.holdTtl() == null ? config.defaultHoldTtl() : request.holdTtl();
        if (ttl.isNegative() || ttl.isZero() || ttl.compareTo(Duration.ofDays(30)) > 0) {
            throw new SubmissionRejected("hold TTL out of permitted range");
        }
        Instant holdUntil = now.plus(ttl);

        String jobId = "job-" + Bytes.b64url(Bytes.random(16));
        String spoolObjectId = "obj-" + Bytes.hex(Bytes.random(16));

        PrintSpec spec = new PrintSpec(safeName(request.documentName()), request.mimeType(),
                request.copies(), request.colorMode(), request.duplex(),
                request.paperSize(), request.pages(), false,
                request.documentClass(), now);

        SpoolEnvelope.Sealed sealed = envelope.seal(jobId, employee.employeeId(),
                request.documentBytes(), spec);
        spool.put(spoolObjectId, SpoolEnvelope.pack(sealed));
        // Plaintext was already copied into the envelope; wipe the caller's copy.
        java.util.Arrays.fill(request.documentBytes(), (byte) 0);

        ReleaseTokenService.Issued token = tokens.issue();
        PrintJob job = new PrintJob(
                jobId,
                employee.employeeId(),
                employee.siteId(),
                employee.collectSites(),
                spec.documentName(),
                spec.documentClass(),
                sealed.ciphertext().length,
                spoolObjectId,
                0,
                spec.colorMode() == ColorMode.COLOR,
                now,
                holdUntil,
                JobState.HELD,
                token.tokenHash(),
                null,
                null,
                null);
        store.saveJob(job);
        return new Submitted(jobId, token.token(), holdUntil);
    }

    private static String safeName(String name) {
        if (name == null || name.isBlank()) {
            return "document";
        }
        String cleaned = name.replaceAll("[\\x00-\\x1F\\x7F/\\\\]", "_");
        return cleaned.length() > 200 ? cleaned.substring(0, 200) : cleaned;
    }

    /** Expected rejection with a client-safe reason. */
    public static final class SubmissionRejected extends RuntimeException {
        public SubmissionRejected(String message) {
            super(message);
        }
    }
}
