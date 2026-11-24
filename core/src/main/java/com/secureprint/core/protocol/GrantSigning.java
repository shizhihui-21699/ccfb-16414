package com.secureprint.core.protocol;

import com.secureprint.core.util.Bytes;
import com.secureprint.core.util.Json;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Canonical signing forms for protocol objects.
 *
 * <p>Both sides must agree byte-for-byte on what was signed, so instead of relying on JSON field
 * order we build an explicit ordered map and serialize with a fixed, documented layout. Fields
 * are added to the end only — never reordered — and the {@code v} field is bumped if the shape
 * ever has to change.
 */
public final class GrantSigning {

    private GrantSigning() {
    }

    public static byte[] canonicalGrant(ReleaseGrant g) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", 1);
        m.put("kind", "release-grant");
        m.put("grantId", g.grantId());
        m.put("jobId", g.jobId());
        m.put("employeeId", g.employeeId());
        m.put("agentId", g.agentId());
        m.put("printerId", g.printerId());
        m.put("nonce", g.nonce());
        m.put("mode", g.mode().name());
        m.put("issuedAt", g.issuedAt().toString());
        m.put("notBefore", g.notBefore().toString());
        m.put("expiresAt", g.expiresAt().toString());
        m.put("wrapTargetFingerprint", g.wrapTargetFingerprint());
        m.put("jobDataKeyWrappedHash", Bytes.sha256Hex(Bytes.utf8(g.jobDataKeyWrapped())));
        return Json.toCanonicalBytes(m);
    }

    public static byte[] canonicalManifest(ReleaseManifest man) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", 1);
        m.put("kind", "release-manifest");
        m.put("manifestId", man.manifestId());
        m.put("agentId", man.agentId());
        m.put("siteId", man.siteId());
        m.put("sequence", man.sequence());
        m.put("issuedAt", man.issuedAt().toString());
        m.put("notBefore", man.notBefore().toString());
        m.put("expiresAt", man.expiresAt().toString());

        // Entries are ordered by jobId so a re-derived manifest is byte-identical regardless of
        // the order the server happened to iterate its store.
        var entries = man.entries().stream()
                .sorted((a, b) -> a.jobId().compareTo(b.jobId()))
                .map(e -> {
                    Map<String, Object> em = new LinkedHashMap<>();
                    em.put("jobId", e.jobId());
                    em.put("employeeId", e.employeeId());
                    em.put("documentName", e.documentName());
                    em.put("holdUntil", e.holdUntil().toString());
                    em.put("spoolObjectId", e.spoolObjectId());
                    em.put("colorOnly", e.colorOnly());
                    em.put("jobDataKeyWrappedHash",
                            Bytes.sha256Hex(Bytes.utf8(e.jobDataKeyWrapped())));
                    return em;
                }).toList();
        m.put("entries", entries);
        return Json.toCanonicalBytes(m);
    }
}
