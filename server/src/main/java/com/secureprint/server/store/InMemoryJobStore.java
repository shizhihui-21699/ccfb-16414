package com.secureprint.server.store;

import com.secureprint.core.domain.Employee;
import com.secureprint.core.domain.JobState;
import com.secureprint.core.domain.PrintJob;
import com.secureprint.core.domain.Printer;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link JobStore}. Every mutation of a job record is done under {@code synchronized}
 * on the store, which makes the compare-and-set style transitions in {@link #claimForRelease}
 * and {@link #claimAllForRelease} atomic.
 *
 * <p>A JDBC implementation must reproduce this with {@code UPDATE ... WHERE state='HELD'} and
 * check the affected-row count; the contract doc on the interface spells that out so nobody
 * "optimises" the check into a read-then-write race.
 */
public final class InMemoryJobStore implements JobStore {

    private final Map<String, PrintJob> jobs = new ConcurrentHashMap<>();
    private final Map<String, Employee> employees = new ConcurrentHashMap<>();
    private final Map<String, String> badgeToEmployee = new ConcurrentHashMap<>();
    private final Map<String, Printer> printers = new ConcurrentHashMap<>();

    @Override
    public void saveJob(PrintJob job) {
        jobs.put(job.jobId(), job);
    }

    @Override
    public Optional<PrintJob> job(String jobId) {
        return Optional.ofNullable(jobs.get(jobId));
    }

    @Override
    public List<PrintJob> jobsFor(String employeeId) {
        return jobs.values().stream()
                .filter(j -> j.ownerEmployeeId().equals(employeeId))
                .sorted(Comparator.comparing(PrintJob::submittedAt))
                .toList();
    }

    @Override
    public List<PrintJob> jobsForSite(String siteId) {
        return jobs.values().stream()
                .filter(j -> j.collectableAt(siteId))
                .sorted(Comparator.comparing(PrintJob::submittedAt))
                .toList();
    }

    @Override
    public List<PrintJob> allJobs() {
        return jobs.values().stream()
                .sorted(Comparator.comparing(PrintJob::submittedAt))
                .toList();
    }

    @Override
    public List<PrintJob> expiredJobs(Instant now, int limit) {
        return jobs.values().stream()
                .filter(j -> (j.state() == JobState.HELD || j.state() == JobState.FAILED)
                        && j.isExpiredAt(now))
                .sorted(Comparator.comparing(PrintJob::holdUntil))
                .limit(limit)
                .toList();
    }

    @Override
    public synchronized boolean claimForRelease(String jobId, String employeeId, Instant now) {
        PrintJob job = jobs.get(jobId);
        if (job == null) {
            return false;
        }
        if (!job.ownerEmployeeId().equals(employeeId)) {
            return false;
        }
        if (job.state() != JobState.HELD) {
            return false;
        }
        if (job.isExpiredAt(now)) {
            return false;
        }
        jobs.put(jobId, job.withState(JobState.RELEASING));
        return true;
    }

    @Override
    public synchronized List<String> claimAllForRelease(String employeeId, Instant now) {
        List<String> claimed = new ArrayList<>();
        for (PrintJob job : jobsFor(employeeId)) {
            if (job.state() == JobState.HELD && !job.isExpiredAt(now)) {
                jobs.put(job.jobId(), job.withState(JobState.RELEASING));
                claimed.add(job.jobId());
            }
        }
        return List.copyOf(claimed);
    }

    @Override
    public synchronized Optional<PrintJob> claimExpired(String jobId, Instant now) {
        PrintJob job = jobs.get(jobId);
        if (job == null) {
            return Optional.empty();
        }
        if (job.state() != JobState.HELD && job.state() != JobState.FAILED) {
            return Optional.empty();
        }
        if (!job.isExpiredAt(now)) {
            return Optional.empty();
        }
        jobs.put(jobId, job.withState(JobState.EXPIRED));
        return Optional.of(job);
    }

    @Override
    public void saveEmployee(Employee employee) {
        employees.put(employee.employeeId(), employee);
        badgeToEmployee.put(employee.badgeUidHash(), employee.employeeId());
    }

    @Override
    public Optional<Employee> employee(String employeeId) {
        return Optional.ofNullable(employees.get(employeeId));
    }

    @Override
    public Optional<Employee> employeeByBadgeHash(String badgeUidHash) {
        String id = badgeToEmployee.get(badgeUidHash);
        return id == null ? Optional.empty() : Optional.ofNullable(employees.get(id));
    }

    @Override
    public void savePrinter(Printer printer) {
        printers.put(printer.printerId(), printer);
    }

    @Override
    public Optional<Printer> printer(String printerId) {
        return Optional.ofNullable(printers.get(printerId));
    }

    @Override
    public List<Printer> printers() {
        return printers.values().stream()
                .sorted(Comparator.comparing(Printer::printerId))
                .toList();
    }

    @Override
    public List<Printer> printersAtSite(String siteId) {
        return printers.values().stream()
                .filter(p -> siteId.equals(p.siteId()))
                .sorted(Comparator.comparing(Printer::printerId))
                .toList();
    }

    @Override
    public void deletePrinter(String printerId) {
        printers.remove(printerId);
    }

    /** Test/introspection helper. */
    public int jobCount() {
        return jobs.size();
    }
}
