package com.secureprint.agent.sync;

import com.secureprint.core.util.Json;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Durable record of offline releases, kept on the agent until the server acknowledges them.
 *
 * <p>Why this exists: while partitioned, the agent can print a job the server still believes is
 * HELD. Without reconciliation the server would later expire "an uncollected payslip" that the
 * employee already has in their hand — and the audit trail would be wrong. Each offline release
 * therefore appends a line here <em>before</em> printing, and the line is removed only after the
 * server acknowledges it.
 *
 * <p>Append-then-print ordering matters: if the agent crashes mid-print, the record still exists
 * and the reconciliation reports "we attempted this", which is the truthful statement. The
 * alternative (record after print) would lose exactly the ambiguous case that an auditor cares
 * about most.
 *
 * <p>Format is newline-delimited JSON — trivially appendable, trivially recoverable after a
 * partial write, and human-readable during an incident.
 */
public final class OfflineJournal {

    private final Path file;

    public OfflineJournal(Path file) {
        this.file = file;
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot create journal dir", e);
        }
    }

    /**
     * One offline release attempt.
     *
     * @param outcome DELIVERED if the device accepted the job, FAILED if delivery failed; an
     *                entry with outcome null means the process died before recording the result
     *                — the reconciler reports it as UNKNOWN rather than guessing.
     */
    public record Entry(String jobId, String employeeId, String printerId, String grantId,
                        Instant at, String outcome, String detail) {

        public Entry withOutcome(String newOutcome, String newDetail) {
            return new Entry(jobId, employeeId, printerId, grantId, at, newOutcome, newDetail);
        }
    }

    /** Appends an attempt before printing. Returns false if already recorded (idempotent). */
    public synchronized boolean appendAttempt(Entry entry) {
        if (contains(entry.jobId())) {
            return false;
        }
        append(entry);
        return true;
    }

    public synchronized void updateOutcome(String jobId, String outcome, String detail) {
        List<Entry> all = readAllInternal();
        List<Entry> rewritten = new ArrayList<>(all.size());
        for (Entry e : all) {
            rewritten.add(e.jobId().equals(jobId) ? e.withOutcome(outcome, detail) : e);
        }
        rewrite(rewritten);
    }

    public synchronized List<Entry> pending() {
        return readAllInternal();
    }

    public synchronized boolean contains(String jobId) {
        return readAllInternal().stream().anyMatch(e -> e.jobId().equals(jobId));
    }

    /** Removes the given job ids after the server has acknowledged them. */
    public synchronized void acknowledge(List<String> jobIds) {
        if (jobIds.isEmpty()) {
            return;
        }
        List<Entry> keep = readAllInternal().stream()
                .filter(e -> !jobIds.contains(e.jobId()))
                .toList();
        rewrite(keep);
    }

    private List<Entry> readAllInternal() {
        if (!Files.exists(file)) {
            return List.of();
        }
        try {
            List<Entry> out = new ArrayList<>();
            for (String line : Files.readAllLines(file)) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    out.add(Json.fromJson(line, Entry.class));
                } catch (RuntimeException ignored) {
                    // A torn final line from a crash mid-append: skip it rather than lose the rest.
                }
            }
            return out;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read journal", e);
        }
    }

    private void append(Entry entry) {
        try {
            Files.writeString(file, Json.toJson(entry) + "\n", StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot append journal", e);
        }
    }

    private void rewrite(List<Entry> entries) {
        try {
            Path tmp = Files.createTempFile(file.toAbsolutePath().getParent(), "journal", ".tmp");
            StringBuilder sb = new StringBuilder();
            for (Entry e : entries) {
                sb.append(Json.toJson(e)).append('\n');
            }
            Files.writeString(tmp, sb.toString());
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot rewrite journal", e);
        }
    }
}
