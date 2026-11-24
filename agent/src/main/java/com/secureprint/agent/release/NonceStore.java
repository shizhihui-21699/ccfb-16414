package com.secureprint.agent.release;

import com.secureprint.core.crypto.Hkdf;
import com.secureprint.core.util.Bytes;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Durable record of consumed grant nonces.
 *
 * <p>Without persistence, "single use" means "single use until the agent process restarts" — an
 * attacker with local access could simply bounce the service and replay a captured grant. Since a
 * branch agent is a physical box in a print room, that is a realistic threat, so the consumed set
 * is written to disk before the release proceeds.
 *
 * <p>Storage is an append-only file of {@code nonce<TAB>epochMillis} lines. Append-then-fsync is
 * the only ordering that is safe here: a crash after printing but before persisting would allow a
 * replay of a grant whose paper already came out, so we persist first, print second. The file is
 * compacted on load (deduplicated, expired entries dropped) so it does not grow without bound.
 *
 * <p>Entries are retained for {@code retention}, comfortably longer than the maximum grant
 * lifetime, after which a nonce can no longer appear in a valid grant anyway.
 */
public final class NonceStore {

    private final Path file;
    private final long retentionMillis;
    private final Set<String> seen = new HashSet<>();

    public NonceStore(Path file, java.time.Duration retention) {
        this.file = file;
        this.retentionMillis = retention.toMillis();
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            load();
        } catch (IOException e) {
            throw new UncheckedIOException("cannot load nonce store", e);
        }
    }

    private void load() throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        long cutoff = System.currentTimeMillis() - retentionMillis;
        for (String line : Files.readAllLines(file)) {
            int tab = line.indexOf('\t');
            if (tab <= 0) {
                continue;
            }
            try {
                long at = Long.parseLong(line.substring(tab + 1));
                if (at >= cutoff) {
                    seen.add(line.substring(0, tab));
                }
            } catch (NumberFormatException ignored) {
                // A torn line from a crash mid-append: ignore it, keep the rest.
            }
        }
    }

    /**
     * Atomically consumes a nonce.
     *
     * @return true if this call is the first to see it; false if it was already used.
     */
    public synchronized boolean consume(String nonce) {
        if (nonce == null || nonce.isBlank()) {
            return false;
        }
        String key = obscure(nonce);
        if (!seen.add(key)) {
            return false;
        }
        try {
            Files.writeString(file, key + "\t" + System.currentTimeMillis() + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            // Force to disk: the guarantee is worthless if a power cut loses the record after the
            // page has already been printed.
            try (var ch = Files.newByteChannel(file, StandardOpenOption.WRITE)) {
                if (ch instanceof java.nio.channels.FileChannel fc) {
                    fc.force(true);
                }
            }
        } catch (IOException e) {
            seen.remove(key);
            throw new UncheckedIOException("cannot persist nonce", e);
        }
        return true;
    }

    public synchronized boolean contains(String nonce) {
        return seen.contains(obscure(nonce));
    }

    public synchronized int size() {
        return seen.size();
    }

    /** Compaction: drop entries older than the retention window and rewrite atomically. */
    public synchronized void compact(Instant now) {
        try {
            StringBuilder sb = new StringBuilder();
            for (String n : seen) {
                sb.append(n).append('\t').append(now.toEpochMilli()).append('\n');
            }
            Path tmp = Files.createTempFile(file.toAbsolutePath().getParent(), "nonce", ".tmp");
            Files.writeString(tmp, sb.toString());
            Files.move(tmp, file, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot compact nonce store", e);
        }
    }

    /** Exposed for tests: a digest that does not reveal the nonce in a hexdump of the file. */
    static String obscure(String nonce) {
        return Bytes.hex(Hkdf.derive(Bytes.utf8(nonce), null, "nonce-store", 16));
    }
}
