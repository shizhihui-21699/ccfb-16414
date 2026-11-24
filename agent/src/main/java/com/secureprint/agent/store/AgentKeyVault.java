package com.secureprint.agent.store;

import com.secureprint.core.crypto.AesGcm;
import com.secureprint.core.crypto.Hkdf;
import com.secureprint.core.util.Json;
import com.secureprint.core.util.Bytes;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;

/**
 * At-rest protection for an agent's local state (its X25519 private key, anti-replay sequence,
 * pending offline release records).
 *
 * <p>An agent lives in a branch office, often in a locked cabinet but not in a data centre. If
 * the box is stolen, the stored private key would let the thief decrypt any spool blob already
 * synced to that site. So everything sensitive is sealed under a key derived from an OS-level
 * secret the application does not itself store (in production: TPM-backed, or a passphrase
 * entered at boot by the site administrator). The demo uses a caller-supplied passphrase.
 *
 * <p>Files are written atomically so a power cut cannot corrupt the only copy of the key.
 */
public final class AgentKeyVault {

    private final Path vaultFile;
    private final byte[] vaultKey;

    public AgentKeyVault(Path vaultFile, String passphrase) {
        if (passphrase == null || passphrase.length() < 12) {
            throw new IllegalArgumentException("vault passphrase must be at least 12 characters");
        }
        this.vaultFile = vaultFile;
        this.vaultKey = Hkdf.derive(Bytes.utf8(passphrase),
                Bytes.utf8("secure-print/agent-vault"), "agent-vault/v1", 32);
    }

    public record VaultState(
            String agentPrivateKeyEncoded,
            String agentPublicKeyEncoded,
            long lastManifestSequence,
            long lastManifestIssuedAtEpochMillis) {

        public VaultState withSequence(long sequence, long issuedAt) {
            return new VaultState(agentPrivateKeyEncoded, agentPublicKeyEncoded, sequence,
                    issuedAt);
        }
    }

    public Optional<VaultState> load() {
        if (!Files.exists(vaultFile)) {
            return Optional.empty();
        }
        try {
            byte[] sealed = Files.readAllBytes(vaultFile);
            byte[] plain = AesGcm.open(vaultKey, sealed, Bytes.utf8("agent-vault"));
            return Optional.of(Json.fromBytes(plain, VaultState.class));
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read agent vault", e);
        }
    }

    public void store(VaultState state) {
        byte[] plain = Json.toBytes(state);
        try {
            byte[] sealed = AesGcm.seal(vaultKey, plain, Bytes.utf8("agent-vault"));
            java.util.Arrays.fill(plain, (byte) 0);
            Path parent = vaultFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = Files.createTempFile(parent, "vault", ".tmp");
            try {
                Files.write(tmp, sealed);
                try (var ch = Files.newByteChannel(tmp)) {
                    if (ch instanceof java.nio.channels.FileChannel fc) {
                        fc.force(true);
                    }
                }
                Files.move(tmp, vaultFile, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write agent vault", e);
        }
    }
}
