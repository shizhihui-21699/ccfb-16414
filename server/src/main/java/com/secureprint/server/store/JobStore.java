package com.secureprint.server.store;

import com.secureprint.core.domain.Employee;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.core.domain.Printer;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Persistence for job metadata, employees and printers.
 *
 * <p>Deliberately an interface: the reference implementation is in-memory, and a production
 * deployment swaps in a JDBC/Redis-backed implementation without touching the services. The
 * <em>only</em> hard requirement is that {@link #claimForRelease} is atomic — that single method
 * is what prevents two people at two printers from both printing the same paycheck.
 */
public interface JobStore {

    void saveJob(PrintJob job);

    Optional<PrintJob> job(String jobId);

    List<PrintJob> jobsFor(String employeeId);

    /** Jobs whose owner's home site is this site, or whose job was routed to it. */
    List<PrintJob> jobsForSite(String siteId);

    /** All jobs, in submission order; used by the sweeper and the admin console. */
    List<PrintJob> allJobs();

    /** All jobs strictly before the given deadline, in submission order. */
    List<PrintJob> expiredJobs(Instant now, int limit);

    /**
     * Atomically transitions HELD → RELEASING. Returns false if the job was already claimed,
     * already released, expired, or cancelled. This is the concurrency control point for the
     * whole release flow: two simultaneous badge taps at different devices produce exactly one
     * winner.
     */
    boolean claimForRelease(String jobId, String employeeId, Instant now);

    /** Atomically claims every HELD job for an employee. Returns the job ids actually claimed. */
    List<String> claimAllForRelease(String employeeId, Instant now);

    /**
     * Atomically transitions an expired HELD/FAILED job to EXPIRED. Returns the prior record if
     * this caller won the transition, empty if the job was already released/claimed/expired.
     * The caller deletes the spool object only after winning; two concurrent sweeps thus
     * produce exactly one deletion and one tombstone.
     */
    Optional<PrintJob> claimExpired(String jobId, Instant now);

    void saveEmployee(Employee employee);

    Optional<Employee> employee(String employeeId);

    Optional<Employee> employeeByBadgeHash(String badgeUidHash);

    void savePrinter(Printer printer);

    Optional<Printer> printer(String printerId);

    List<Printer> printers();

    List<Printer> printersAtSite(String siteId);

    void deletePrinter(String printerId);
}
