# SecurePrint

企业安全打印刷卡释放服务 — badge-release printing for payroll and contracts.

Print jobs are **held encrypted on the server** and only come out of a printer after the employee
badge-taps or QR-scans at **any** managed device. A document that finishes printing is never
sitting in an output tray for a passer-by to pick up.

```bash
./gradlew test        # 130 tests
./gradlew :app:run    # end-to-end demo, prints each step
```

## The five hard problems, and where the answer lives

| Problem | Solution | Where |
|---|---|---|
| A dozen-plus printer brands, all different | One `PrinterDriver` interface; raster-first PDL pipeline (PCL5 / PostScript / IPP); model→driver registry with protocol fallback | `drivers/` |
| Employees print at branch offices while travelling | `collectSites` routing snapshot; site-bound agents; same badge everywhere | `core/domain`, `server/service/ReleaseService` |
| Printer ↔ server network goes down | Signed, short-lived manifests carrying per-agent-wrapped job keys; local encrypted spool; journal + reconciliation on reconnect | `agent/` |
| Documents must be protected while held | AES-256-GCM envelope encryption, per-job data key, HKDF-separated KEKs, AAD binds job+owner; crypto-shred on destroy | `core/store/SpoolEnvelope` |
| Uncollected jobs must self-destruct | Atomic expiry claim → delete blob → tombstone; unrecoverable by construction | `server/service/ExpirySweeper` |

Full reasoning, threat model and the honest limitations of partition-tolerant printing are in
**[docs/DESIGN.md](docs/DESIGN.md)**.

## Reading order for a reviewer

1. `core/store/SpoolEnvelope.java` — what "encrypted at rest" actually means here, and why deleting
   a job is cryptographic rather than cosmetic.
2. `server/service/ReleaseService.java` — the online release decision, and the one atomic claim that
   makes "exactly one printer" true under concurrency.
3. `agent/release/ReleaseEngine.java` — the offline enforcement point. This is where a stolen branch
   box must fail closed; every check is listed in the class comment.
4. `agent/sync/OfflineReconciler.java` — how the system avoids lying in its audit trail after a
   partition.
5. `docs/DESIGN.md` §4.3 — the limitation nobody should discover in production.

## What this is not

A runnable reference implementation, not a shippable product. The productionisation checklist
(KMS, mTLS, JDBC store, key rotation, per-model device acceptance) is in
[docs/DESIGN.md §8](docs/DESIGN.md).
