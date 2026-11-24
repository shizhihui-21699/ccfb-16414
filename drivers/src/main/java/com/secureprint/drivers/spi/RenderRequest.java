package com.secureprint.drivers.spi;

import com.secureprint.core.domain.PrintSpec;

/**
 * A job to render, in neutral terms. {@code documentBytes} is the decrypted document, valid only
 * for the duration of the {@code deliver} call — drivers must not retain or copy it.
 */
public record RenderRequest(
        String jobId,
        String documentName,
        String mimeType,
        byte[] documentBytes,
        PrintSpec spec,
        String releaseGrantId,
        String employeeId) {

    public RenderRequest {
        if (jobId == null || documentBytes == null) {
            throw new IllegalArgumentException("jobId and documentBytes required");
        }
    }
}
