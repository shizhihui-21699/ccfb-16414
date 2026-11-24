package com.secureprint.drivers.transport;

import com.secureprint.core.domain.ColorMode;
import com.secureprint.core.domain.DuplexMode;
import com.secureprint.core.domain.PrintSpec;
import com.secureprint.core.util.Bytes;
import com.secureprint.drivers.spi.DeviceSession;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * IPP 1.1 client (RFC 8011), enough of it to submit a document and read job state.
 *
 * <p>IPP is the right transport for printers that expose it (nearly all modern MFPs and every
 * CUPS/AirPrint-capable device), because unlike raw 9100 it gives a per-job id and an authentic
 * "did the device accept this" answer. Raw 9100 only tells you the TCP write succeeded, which
 * is not the same thing.
 *
 * <p>Scope is deliberately narrow: Print-Job, Get-Job-Attributes, Cancel-Job. Anything fancier
 * (subscriptions, event notifications) is out of scope for a release service.
 */
public final class IppTransport {

    private static final byte VERSION_MAJOR = 1;
    private static final byte VERSION_MINOR = 1;

    private static final byte OP_PRINT_JOB = 0x02;
    private static final byte OP_CANCEL_JOB = 0x08;
    private static final byte OP_GET_JOB_ATTRIBUTES = 0x09;

    // Delimiter tags (RFC 8011 §3.5.1).
    private static final byte GROUP_OPERATION = 0x01;
    private static final byte GROUP_END = 0x03;

    // Value tags.
    private static final byte TAG_INTEGER = 0x21;
    private static final byte TAG_KEYWORD = 0x44;
    private static final byte TAG_URI = 0x45;
    private static final byte TAG_NAME = 0x42;
    private static final byte TAG_CHARSET = 0x47;
    private static final byte TAG_NATURAL_LANGUAGE = 0x48;

    /** Outcome of a Print-Job: job-id is 0 when the device replied with an error. */
    public record PrintResult(int jobId, String statusText, int statusCode) {
        public boolean accepted() {
            return jobId > 0 && statusCode < 0x0100;
        }
    }

    private final String username;

    public IppTransport(String username) {
        this.username = username == null ? "secure-print" : username;
    }

    public PrintResult printJob(DeviceSession session, byte[] document, PrintSpec spec) {
        String printerUri = printerUri(session);
        ByteArrayOutputStream body = new ByteArrayOutputStream(4096);

        byte[] requestId = Bytes.random(4);
        writeHeader(body, OP_PRINT_JOB, requestId);

        startGroup(body, GROUP_OPERATION);
        attrName(body, TAG_CHARSET, "attributes-charset", "utf-8");
        attrName(body, TAG_NATURAL_LANGUAGE, "attributes-natural-language", "en");
        attrName(body, TAG_URI, "printer-uri", printerUri);
        attrKeyword(body, "requesting-user-name", username);
        attrName(body, TAG_NAME, "job-name", safeJobName(spec.documentName()));
        attrKeyword(body, "document-format", "application/octet-stream");

        if (spec.copies() > 1) {
            attrInteger(body, "copies", spec.copies());
        }
        if (spec.colorMode() == ColorMode.MONO) {
            attrKeyword(body, "print-color-mode", "monochrome");
        }
        if (spec.duplex() != DuplexMode.SIMPLEX) {
            attrKeyword(body, "sides", spec.duplex() == DuplexMode.SHORT_EDGE
                    ? "two-sided-short-edge" : "two-sided-long-edge");
        }
        body.write(GROUP_END);

        try {
            body.write(document);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        byte[] response = exchange(session, body.toByteArray(), requestId);
        return parsePrintResponse(response);
    }

    public int cancelJob(DeviceSession session, int jobId) {
        ByteArrayOutputStream body = new ByteArrayOutputStream(512);
        byte[] requestId = Bytes.random(4);
        writeHeader(body, OP_CANCEL_JOB, requestId);
        startGroup(body, GROUP_OPERATION);
        attrName(body, TAG_CHARSET, "attributes-charset", "utf-8");
        attrName(body, TAG_NATURAL_LANGUAGE, "attributes-natural-language", "en");
        attrName(body, TAG_URI, "printer-uri", printerUri(session));
        attrInteger(body, "job-id", jobId);
        attrKeyword(body, "requesting-user-name", username);
        body.write(GROUP_END);
        byte[] response = exchange(session, body.toByteArray(), requestId);
        int idx = response.length - 2;
        if (idx < 0) {
            return -1;
        }
        return ((response[idx] & 0xFF) << 8) | (response[idx + 1] & 0xFF);
    }

    public String jobState(DeviceSession session, int jobId) {
        ByteArrayOutputStream body = new ByteArrayOutputStream(512);
        byte[] requestId = Bytes.random(4);
        writeHeader(body, OP_GET_JOB_ATTRIBUTES, requestId);
        startGroup(body, GROUP_OPERATION);
        attrName(body, TAG_CHARSET, "attributes-charset", "utf-8");
        attrName(body, TAG_NATURAL_LANGUAGE, "attributes-natural-language", "en");
        attrName(body, TAG_URI, "printer-uri", printerUri(session));
        attrInteger(body, "job-id", jobId);
        body.write(GROUP_END);
        byte[] response = exchange(session, body.toByteArray(), requestId);
        String text = new String(response, StandardCharsets.ISO_8859_1);
        for (String state : new String[]{"completed", "processing", "pending", "canceled", "aborted"}) {
            if (text.contains(state)) {
                return state;
            }
        }
        return "unknown";
    }

    private String printerUri(DeviceSession session) {
        return (session.tls() ? "ipps" : "ipp") + "://" + session.host() + ":" + session.port()
                + "/" + (session.queueName() == null || session.queueName().isBlank()
                ? "printers/default" : "printers/" + session.queueName());
    }

    private byte[] exchange(DeviceSession session, byte[] request, byte[] requestId) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(session.host(), session.port()),
                    session.timeoutMillis());
            socket.setSoTimeout(session.timeoutMillis());
            var out = socket.getOutputStream();
            out.write(request);
            out.flush();
            socket.shutdownOutput();
            return socket.getInputStream().readAllBytes();
        } catch (IOException e) {
            throw new com.secureprint.drivers.spi.DriverException("ipp",
                    "IPP exchange with " + session.host() + ":" + session.port()
                            + " failed: " + e.getMessage(), false, e);
        }
    }

    private static PrintResult parsePrintResponse(byte[] response) {
        if (response.length < 8) {
            return new PrintResult(0, "empty IPP response", -1);
        }
        int statusCode = readIppStatus(response);
        int jobId = findJobId(response);
        String statusText = describeStatus(statusCode);
        return new PrintResult(jobId, statusText, statusCode);
    }

    private static int readIppStatus(byte[] response) {
        if (response.length < 2) {
            return -1;
        }
        return ((response[2] & 0xFF) << 8) | (response[3] & 0xFF);
    }

    /** Scans the flat attribute encoding for job-id. Robust enough for our own requests only. */
    private static int findJobId(byte[] response) {
        byte[] needle = "job-id".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i + needle.length + 5 < response.length; i++) {
            boolean match = true;
            for (int k = 0; k < needle.length; k++) {
                if (response[i + k] != needle[k]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                int after = i + needle.length;
                // name-length(2) then value-length(2) then the 4-byte integer
                int lenPos = after;
                int valueLenPos = lenPos + 2 + (response[lenPos] & 0xFF);
                if (valueLenPos + 4 > response.length) {
                    return 0;
                }
                int nameLen = ((response[lenPos] & 0xFF) << 8) | (response[lenPos + 1] & 0xFF);
                int valuePos = lenPos + 2 + nameLen + 2;
                if (valuePos + 4 > response.length) {
                    return 0;
                }
                return ((response[valuePos] & 0xFF) << 24)
                        | ((response[valuePos + 1] & 0xFF) << 16)
                        | ((response[valuePos + 2] & 0xFF) << 8)
                        | (response[valuePos + 3] & 0xFF);
            }
        }
        return 0;
    }

    private static String describeStatus(int code) {
        return switch (code) {
            case 0x0000 -> "successful-ok";
            case 0x0400 -> "client-error-bad-request";
            case 0x0401 -> "client-error-forbidden";
            case 0x0403 -> "client-error-not-authenticated";
            case 0x0404 -> "client-error-not-possible";
            case 0x0500 -> "server-error-internal-error";
            case 0x0501 -> "server-error-operation-not-supported";
            case 0x0502 -> "server-error-service-unavailable";
            default -> "ipp-status-0x" + Integer.toHexString(code);
        };
    }

    private static void writeHeader(ByteArrayOutputStream out, byte op, byte[] requestId) {
        out.write(VERSION_MAJOR);
        out.write(VERSION_MINOR);
        out.write(op);
        out.write(requestId, 0, 4);
    }

    private static void startGroup(ByteArrayOutputStream out, byte group) {
        out.write(group);
    }

    private static void attrName(ByteArrayOutputStream out, byte tag, String name, String value) {
        writeAttr(out, tag, name, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void attrKeyword(ByteArrayOutputStream out, String name, String value) {
        writeAttr(out, TAG_KEYWORD, name, value.getBytes(StandardCharsets.US_ASCII));
    }

    private static void attrInteger(ByteArrayOutputStream out, String name, int value) {
        writeAttr(out, TAG_INTEGER, name, new byte[]{
                (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value});
    }

    private static void writeAttr(ByteArrayOutputStream out, byte tag, String name, byte[] value) {
        out.write(tag);
        out.write((name.length() >> 8) & 0xFF);
        out.write(name.length() & 0xFF);
        out.writeBytes(name.getBytes(StandardCharsets.US_ASCII));
        out.write((value.length >> 8) & 0xFF);
        out.write(value.length & 0xFF);
        out.writeBytes(value);
    }

    private static String safeJobName(String name) {
        if (name == null || name.isBlank()) {
            return "secure-print";
        }
        String cleaned = name.replaceAll("[\\x00-\\x1F\\x7F]", "");
        return cleaned.length() > 200 ? cleaned.substring(0, 200) : cleaned;
    }
}
