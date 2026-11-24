package com.secureprint.app;

import com.secureprint.core.domain.Capability;
import com.secureprint.core.protocol.ReleaseManifest;
import com.secureprint.core.util.Json;
import com.secureprint.server.service.AgentRegistry;
import com.secureprint.server.service.ManifestService;
import com.secureprint.server.store.InMemoryJobStore;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;

/**
 * Minimal HTTP surface over the release system, built on the JDK's own server so the project
 * has no web-framework dependency to audit.
 *
 * <p>In a real deployment this sits behind the corporate API gateway, which terminates TLS and
 * performs mutual-TLS for agent traffic. The endpoints are deliberately few:
 *
 * <pre>
 *   POST /v1/jobs                    submit a document (employee auth via SSO upstream)
 *   GET  /v1/jobs?employee=&site=    list held jobs at a site
 *   POST /v1/release                 mint a release grant for one job
 *   POST /v1/release/confirm         agent reports a successful print
 *   POST /v1/release/fail            agent reports a failure
 *   POST /v1/jobs/{id}/cancel        employee cancels
 *   GET  /v1/agents/{id}/manifest    pull the offline manifest + blobs
 *   POST /v1/agents/{id}/ack         agent acknowledges the manifest sequence
 *   GET  /health                     liveness + inventory counts
 * </pre>
 *
 * <p>Not modelled here, because they belong to the gateway rather than this service: SSO/employee
 * authentication for the submit endpoint, mutual TLS for agent endpoints, and rate limiting.
 * The code is structured so those are gateway concerns, not application ones — the application
 * still re-checks every authority decision itself, so a gateway misconfiguration degrades
 * availability, not confidentiality.
 */
public final class HttpApi {

    private final SecurePrintSystem system;
    private final int port;
    private HttpServer server;

    public HttpApi(SecurePrintSystem system, int port) {
        this.system = system;
        this.port = port;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.createContext("/health", this::health);
        server.createContext("/v1/jobs", this::jobs);
        server.createContext("/v1/release", this::release);
        server.createContext("/v1/agents", this::agents);
        server.start();
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    public int boundPort() {
        return server.getAddress().getPort();
    }

    // ---------------- handlers ----------------

    private void health(HttpExchange ex) throws IOException {
        respond(ex, 200, system.health());
    }

    private void jobs(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        if ("POST".equals(ex.getRequestMethod()) && path.equals("/v1/jobs")) {
            submitJob(ex);
            return;
        }
        if (path.matches("/v1/jobs/[^/]+/cancel")) {
            String jobId = path.split("/")[3];
            Map<String, String> q = query(ex);
            boolean ok = system.cancel(jobId, q.get("employee"));
            respond(ex, ok ? 200 : 409, Map.of("cancelled", ok));
            return;
        }
        Map<String, String> q = query(ex);
        String employeeId = q.get("employee");
        if (employeeId == null || employeeId.isBlank()) {
            // Without an employee identity in the query this endpoint would enumerate every held
            // document's name in the company. Identity must come from the gateway (SSO), so an
            // anonymous caller gets nothing to look at.
            respond(ex, 400, Map.of("error", "employee query parameter required"));
            return;
        }
        List<Map<String, Object>> jobs = system.pending(employeeId, q.get("site")).stream()
                .map(j -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("jobId", j.jobId());
                    m.put("documentName", j.documentName());
                    m.put("documentClass", j.documentClass());
                    m.put("sizeBytes", j.sizeBytes());
                    m.put("holdUntil", j.holdUntil().toString());
                    m.put("collectSites", j.collectSites());
                    return m;
                }).toList();
        respond(ex, 200, Map.of("jobs", jobs));
    }

    private void submitJob(HttpExchange ex) throws IOException {
        Map<String, Object> body = Json.toObjectMap(ex.getRequestBody().readAllBytes());
        String employeeId = str(body.get("employeeId"));
        String documentName = str(body.get("documentName"));
        String mimeType = str(body.getOrDefault("mimeType", "text/plain"));
        byte[] doc = Base64.getDecoder().decode(str(body.get("documentBase64")));
        var submitted = system.submit(employeeId, documentName, mimeType, doc);
        respond(ex, 201, Map.of(
                "jobId", submitted.jobId(),
                "releaseToken", submitted.releaseToken(),
                "holdUntil", submitted.holdUntil().toString()));
    }

    private void release(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        Map<String, Object> body = Json.toObjectMap(ex.getRequestBody().readAllBytes());
        if (path.endsWith("/confirm")) {
            system.confirmReleased(str(body.get("agentId")), str(body.get("jobId")));
            respond(ex, 200, Map.of("confirmed", true));
            return;
        }
        if (path.endsWith("/fail")) {
            system.confirmFailed(str(body.get("agentId")), str(body.get("jobId")),
                    str(body.getOrDefault("reason", "unknown")),
                    Boolean.TRUE.equals(body.get("retryable")));
            respond(ex, 200, Map.of("recorded", true));
            return;
        }
        try {
            var grant = system.release(str(body.get("jobId")), str(body.get("employeeId")),
                    str(body.get("releaseToken")), str(body.get("agentId")),
                    str(body.get("printerId")));
            respond(ex, 200, Map.of("grant", Json.tree(grant.grantJson()),
                    "signature", grant.signatureB64()));
        } catch (com.secureprint.server.service.ReleaseService.ReleaseDenied denied) {
            respond(ex, 403, Map.of("error", denied.getMessage()));
        }
    }

    private void agents(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        // /v1/agents/{id}/manifest and /v1/agents/{id}/ack
        String[] parts = path.split("/");
        if (parts.length < 4) {
            respond(ex, 404, Map.of("error", "not found"));
            return;
        }
        String agentId = parts[3];
        if (path.endsWith("/manifest")) {
            var bundle = system.manifests.buildForAgent(agentId);
            if (bundle.isEmpty()) {
                respond(ex, 404, Map.of("error", "unknown agent"));
                return;
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("manifest", Json.tree(Json.toJson(bundle.get().manifest())));
            out.put("signature", bundle.get().signatureB64());
            Map<String, Object> blobs = new LinkedHashMap<>();
            for (var blob : bundle.get().blobs()) {
                blobs.put(blob.objectId(), Base64.getEncoder().encodeToString(blob.packed()));
            }
            out.put("blobs", blobs);
            system.audit.record(com.secureprint.server.service.AuditingService.Action.MANIFEST_ISSUED,
                    null, "SYSTEM", null, null, bundle.get().manifest().siteId(),
                    "agent=" + agentId + " seq=" + bundle.get().manifest().sequence());
            respond(ex, 200, out);
            return;
        }
        if (path.endsWith("/ack")) {
            Map<String, Object> body = Json.toObjectMap(ex.getRequestBody().readAllBytes());
            long seq = ((Number) body.get("sequence")).longValue();
            system.manifests.acknowledge(agentId, seq);
            respond(ex, 200, Map.of("acknowledged", seq));
            return;
        }
        respond(ex, 404, Map.of("error", "not found"));
    }

    // ---------------- helpers ----------------

    private static Map<String, String> query(HttpExchange ex) {
        Map<String, String> out = new HashMap<>();
        String q = ex.getRequestURI().getQuery();
        if (q == null) {
            return out;
        }
        for (String pair : q.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                out.put(java.net.URLDecoder.decode(pair.substring(0, eq),
                                StandardCharsets.UTF_8),
                        java.net.URLDecoder.decode(pair.substring(eq + 1),
                                StandardCharsets.UTF_8));
            }
        }
        return out;
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }

    private static void respond(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = Json.toBytes(body);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }
}
