package com.secureprint.core.domain;

import java.time.Instant;
import java.util.Set;

/**
 * A badge-to-employee binding as known by the central directory.
 *
 * <p>The {@code badgeUidHash} is the only form of the badge UID that ever leaves a reader: raw
 * UIDs are salted-hashed at capture time so a directory dump cannot be replayed onto a
 * badge emulator.
 *
 * <p>{@code travelSiteIds} is what makes <em>collecting a print at a branch office</em> work: the
 * directory (fed by HR travel bookings or simply configured by an admin) lists the sites where
 * this employee is currently expected, and submission copies that set onto the job so branch
 * agents know to pre-fetch it. Empty means "home site only". A value of {@code "*"} means "any
 * site" and is reserved for roles that explicitly need it (auditors, executives); it is not a
 * default.
 */
public record Employee(
        String employeeId,
        String displayName,
        String department,
        String email,
        String badgeUidHash,
        String siteId,
        Set<String> travelSiteIds,
        boolean active,
        Instant updatedAt) {

    public static final String ANY_SITE = "*";

    public Employee {
        if (employeeId == null || employeeId.isBlank()) {
            throw new IllegalArgumentException("employeeId required");
        }
        if (badgeUidHash == null || badgeUidHash.isBlank()) {
            throw new IllegalArgumentException("badgeUidHash required");
        }
        travelSiteIds = travelSiteIds == null ? Set.of() : Set.copyOf(travelSiteIds);
    }

    /** Convenience constructor for employees who only ever print at their home site. */
    public Employee(String employeeId, String displayName, String department, String email,
                    String badgeUidHash, String siteId, boolean active, Instant updatedAt) {
        this(employeeId, displayName, department, email, badgeUidHash, siteId, Set.of(), active,
                updatedAt);
    }

    /** Where this employee's jobs may be collected. */
    public Set<String> collectSites() {
        Set<String> sites = new java.util.LinkedHashSet<>(travelSiteIds);
        sites.add(siteId);
        return Set.copyOf(sites);
    }

    public boolean canCollectAt(String site) {
        return travelSiteIds.contains(ANY_SITE) || siteId.equals(site)
                || travelSiteIds.contains(site);
    }

    public Employee withBadgeHash(String newHash, Instant when) {
        return new Employee(employeeId, displayName, department, email, newHash, siteId,
                travelSiteIds, active, when);
    }

    public Employee travellingTo(Set<String> sites) {
        return new Employee(employeeId, displayName, department, email, badgeUidHash, siteId,
                sites, active, updatedAt);
    }
}
