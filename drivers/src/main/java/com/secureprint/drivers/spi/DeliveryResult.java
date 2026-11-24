package com.secureprint.drivers.spi;

/** Device accepted the job. {@code deviceJobId} lets us cancel or reconcile later. */
public record DeliveryResult(
        String deviceJobId,
        int pagesDelivered,
        int bytesDelivered,
        String pdlUsed) {

    public DeliveryResult {
        if (deviceJobId == null) {
            deviceJobId = "";
        }
        pdlUsed = pdlUsed == null ? "unknown" : pdlUsed;
    }
}
