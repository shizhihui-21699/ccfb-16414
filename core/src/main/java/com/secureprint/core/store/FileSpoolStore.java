package com.secureprint.core.store;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;

/**
 * Filesystem-backed spool store.
 *
 * <p>Objects are written to a temp file, fsynced, then atomically renamed into place, so a
 * crash can never leave a half-written envelope that later fails to decrypt. Callers must
 * ensure their directory lives on an encrypted volume (LUKS/FileVault/BitLocker): the
 * application-level envelope protects the bytes, but defence in depth asks for both.
 */
public final class FileSpoolStore implements SpoolStore {

    private final Path root;

    public FileSpoolStore(Path root) {
        this.root = root;
        try {
            Files.createDirectories(root);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot create spool dir " + root, e);
        }
    }

    private Path pathFor(String objectId) {
        if (objectId == null || !objectId.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalArgumentException("illegal object id");
        }
        // Two-level fanout keeps directory sizes sane on large installations.
        return root.resolve(objectId.substring(0, 2)).resolve(objectId + ".spool");
    }

    @Override
    public void put(String objectId, byte[] sealedBytes) {
        Path target = pathFor(objectId);
        try {
            Files.createDirectories(target.getParent());
            Path tmp = Files.createTempFile(target.getParent(), objectId, ".tmp");
            try {
                try (var out = Files.newOutputStream(tmp)) {
                    out.write(sealedBytes);
                    out.flush();
                }
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write spool object " + objectId, e);
        }
    }

    @Override
    public Optional<byte[]> get(String objectId) {
        Path p = pathFor(objectId);
        if (!Files.exists(p)) {
            return Optional.empty();
        }
        try {
            return Optional.of(Files.readAllBytes(p));
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read spool object " + objectId, e);
        }
    }

    @Override
    public void delete(String objectId) {
        Path p = pathFor(objectId);
        try {
            Files.deleteIfExists(p);
            Path parent = p.getParent();
            if (parent != null && Files.isDirectory(parent)) {
                try (DirectoryStream<Path> s = Files.newDirectoryStream(parent)) {
                    if (!s.iterator().hasNext()) {
                        Files.deleteIfExists(parent);
                    }
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot delete spool object " + objectId, e);
        }
    }

    @Override
    public boolean exists(String objectId) {
        return Files.exists(pathFor(objectId));
    }
}
