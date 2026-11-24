package com.secureprint.app;

import com.secureprint.core.domain.Capability;
import com.secureprint.core.util.Json;
import com.secureprint.server.config.ServerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Exercises the HTTP surface end to end, including the agent manifest pull. */
class HttpApiTest {

    private Path dir;
    private SecurePrintSystem system;
    private HttpApi api;
    private String base;
    private final HttpClient client = HttpClient.newHttpClient();

    @BeforeEach
    void setUp() throws Exception {
        dir = Files.createTempDirectory("http-api-test");
        system = new SecurePrintSystem(dir.resolve("spool"), ServerConfig.ephemeralDefaults(),
                Clock.fixed(Instant.parse("2026-11-25T09:00:00Z"), ZoneOffset.UTC));
        system.addEmployee("emp-1", "Li Wei", "Finance", "li@x", "4A1B9C2D", "site-shanghai",
                Set.of("site-suzhou"));
        system.addPrinter("prn-sz", "Kyocera", "kyocera.ecosys.pcl5.raw9100", "site-suzhou",
                "127.0.0.1", 9100, EnumSet.of(Capability.MONO, Capability.A4));
        system.enrollAgent("agent-sz", "site-suzhou");
        api = new HttpApi(system, 0);
        api.start();
        base = "http://127.0.0.1:" + api.boundPort();
    }

    @AfterEach
    void tearDown() throws Exception {
        api.stop();
        try (var walk = Files.walk(dir)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                    // best effort
                }
            });
        }
    }

    private HttpResponse<String> post(String path, Object body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + path))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(Json.toJson(body)))
                        .build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private HttpResponse<String> get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    @Test
    void healthReportsInventory() throws Exception {
        var response = get("/health");
        assertEquals(200, response.statusCode());
        Map<String, Object> body = Json.toObjectMap(
                response.body().getBytes(StandardCharsets.UTF_8));
        assertEquals("ok", body.get("status"));
        assertEquals(1, ((Number) body.get("printers")).intValue());
    }

    @Test
    void submitThenListThenReleaseOverHttp() throws Exception {
        var submit = post("/v1/jobs", Map.of(
                "employeeId", "emp-1",
                "documentName", "payslip.txt",
                "mimeType", "text/plain",
                "documentBase64", Base64.getEncoder().encodeToString(
                        "NET PAY".getBytes(StandardCharsets.UTF_8))));
        assertEquals(201, submit.statusCode());
        Map<String, Object> submitted = Json.toObjectMap(
                submit.body().getBytes(StandardCharsets.UTF_8));
        String jobId = (String) submitted.get("jobId");
        String token = (String) submitted.get("releaseToken");

        var list = get("/v1/jobs?employee=emp-1&site=site-suzhou");
        assertEquals(200, list.statusCode());
        assertTrue(list.body().contains(jobId), "travelling employee's job listed at branch");

        var release = post("/v1/release", Map.of("jobId", jobId, "employeeId", "emp-1",
                "releaseToken", token, "agentId", "agent-sz", "printerId", "prn-sz"));
        assertEquals(200, release.statusCode());
        assertTrue(release.body().contains("signature"));
    }

    @Test
    void releaseWithBadTokenIsForbidden() throws Exception {
        var submit = post("/v1/jobs", Map.of("employeeId", "emp-1", "documentName", "p.txt",
                "mimeType", "text/plain", "documentBase64", Base64.getEncoder()
                        .encodeToString("x".getBytes(StandardCharsets.UTF_8))));
        String jobId = (String) Json.toObjectMap(submit.body().getBytes(
                StandardCharsets.UTF_8)).get("jobId");

        var release = post("/v1/release", Map.of("jobId", jobId, "employeeId", "emp-1",
                "releaseToken", "nope", "agentId", "agent-sz", "printerId", "prn-sz"));
        assertEquals(403, release.statusCode());
        assertTrue(release.body().contains("invalid release token"));
    }

    @Test
    void agentPullsManifestAndBlobs() throws Exception {
        post("/v1/jobs", Map.of("employeeId", "emp-1", "documentName", "p.txt",
                "mimeType", "text/plain", "documentBase64", Base64.getEncoder()
                        .encodeToString("hello".getBytes(StandardCharsets.UTF_8))));

        var manifest = get("/v1/agents/agent-sz/manifest");
        assertEquals(200, manifest.statusCode());
        Map<String, Object> body = Json.toObjectMap(
                manifest.body().getBytes(StandardCharsets.UTF_8));
        assertTrue(body.containsKey("manifest"));
        assertTrue(body.containsKey("signature"));
        assertTrue(body.get("blobs") instanceof Map<?, ?> blobs && blobs.size() == 1);
    }

    @Test
    void jobListingWithoutEmployeeIsRejected() throws Exception {
        assertEquals(400, get("/v1/jobs").statusCode(),
                "an anonymous listing would enumerate every held document name");
    }

    @Test
    void unknownAgentManifestIs404() throws Exception {
        assertEquals(404, get("/v1/agents/ghost/manifest").statusCode());
    }

    @Test
    void cancelEndpointReflectsOwnership() throws Exception {
        var submit = post("/v1/jobs", Map.of("employeeId", "emp-1", "documentName", "p.txt",
                "mimeType", "text/plain", "documentBase64", Base64.getEncoder()
                        .encodeToString("x".getBytes(StandardCharsets.UTF_8))));
        String jobId = (String) Json.toObjectMap(submit.body().getBytes(
                StandardCharsets.UTF_8)).get("jobId");

        assertEquals(409, post("/v1/jobs/" + jobId + "/cancel?employee=emp-2", Map.of())
                .statusCode());
        assertEquals(200, post("/v1/jobs/" + jobId + "/cancel?employee=emp-1", Map.of())
                .statusCode());
    }

    @Test
    void auditTrailRecordsSubmissionAndRelease() throws Exception {
        var submit = post("/v1/jobs", Map.of("employeeId", "emp-1", "documentName", "p.txt",
                "mimeType", "text/plain", "documentBase64", Base64.getEncoder()
                        .encodeToString("x".getBytes(StandardCharsets.UTF_8))));
        Map<String, Object> submitted = Json.toObjectMap(
                submit.body().getBytes(StandardCharsets.UTF_8));
        post("/v1/release", Map.of("jobId", submitted.get("jobId"), "employeeId", "emp-1",
                "releaseToken", submitted.get("releaseToken"), "agentId", "agent-sz",
                "printerId", "prn-sz"));

        var actions = system.audit.snapshot().stream().map(e -> e.action()).toList();
        assertTrue(actions.contains("JOB_SUBMITTED"));
        assertTrue(actions.contains("RELEASE_GRANTED"));
        assertTrue(system.audit.verifyChain());
    }
}
