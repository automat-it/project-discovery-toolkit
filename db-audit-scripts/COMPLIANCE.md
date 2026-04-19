# Compliance Control Mapping

This document maps each audit script in `db-audit-scripts/` to the security
and operational controls it helps evidence across common compliance
frameworks: **CIS** (engine-specific benchmarks), **PCI DSS v4.0**,
**HIPAA** (Security Rule), and **SOC 2** (Trust Services Criteria).

The mapping is advisory — it identifies scripts whose output is *relevant
evidence* for a control. A passing audit still requires human
interpretation of the output (e.g., a weak cipher listed by
`sec_07_encryption_status.sql` is only a finding if your policy forbids it).

## How to use

1. Run the full suite for an engine:
   ```
   for f in db-audit-scripts/<engine>/**/*.sql; do run "$f" > out/$(basename $f).txt; done
   ```
2. Match each required control from your auditor's checklist against the
   table below.
3. Attach the relevant output file(s) as evidence.

## Script → Control mapping

Controls are listed per family. Engines are abbreviated PG / MY / MS where a
script exists for all three.

### Access Control & Identity

| Script (all engines) | CIS | PCI DSS v4.0 | HIPAA Security Rule | SOC 2 TSC |
|---|---|---|---|---|
| `sec_01_users_and_privileges` | Access Control | 7.2, 8.2 | §164.308(a)(4), §164.312(a)(1) | CC6.1, CC6.2, CC6.3 |
| `sec_02_role_membership_graph` | Access Control | 7.2 | §164.308(a)(4) | CC6.1, CC6.3 |
| `sec_03_public_role_privileges` | Access Control | 7.2.5 | §164.308(a)(4) | CC6.1 |
| `sec_04_object_ownership` | Access Control | 7.2 | §164.308(a)(4) | CC6.1 |
| `sec_11_role_inheritance_chains` | Access Control | 7.2.4 | §164.308(a)(4) | CC6.1, CC6.3 |
| `sec_12_dormant_users` | Access Control | 8.2.6 | §164.308(a)(3)(ii)(C) | CC6.2, CC6.3 |
| `sec_13_service_accounts` | Access Control | 8.6 | §164.308(a)(4) | CC6.1 |

### Authentication

| Script (all engines) | CIS | PCI DSS v4.0 | HIPAA Security Rule | SOC 2 TSC |
|---|---|---|---|---|
| `sec_05_password_policies` | Password Policy | 8.3.6, 8.3.7 | §164.308(a)(5)(ii)(D) | CC6.1 |
| `sec_20_failed_login_patterns` | Monitoring | 10.2.1.1, 8.3.4 | §164.312(b) | CC7.2, CC7.3 |

### Audit Logging

| Script (all engines) | CIS | PCI DSS v4.0 | HIPAA Security Rule | SOC 2 TSC |
|---|---|---|---|---|
| `sec_06_audit_logging` | Audit & Logging | 10.2, 10.3 | §164.312(b) | CC7.2 |
| `sec_18_audit_gaps` | Audit & Logging | 10.2.1 | §164.312(b) | CC7.2, CC7.3 |
| `sec_19_schema_change_history` | Change Management | 6.5.5, 10.2.1.5 | §164.312(b), §164.308(a)(1)(ii)(D) | CC7.1, CC7.2, CC8.1 |

### Encryption & Data Protection

| Script (all engines) | CIS | PCI DSS v4.0 | HIPAA Security Rule | SOC 2 TSC |
|---|---|---|---|---|
| `sec_07_encryption_status` | Cryptography | 3.5, 4.2.1 | §164.312(a)(2)(iv), §164.312(e)(2)(ii) | CC6.1, CC6.7 |
| `sec_09_sensitive_data_discovery` | Data Classification | 3.2, 3.3 | §164.308(a)(1)(ii)(A) | CC6.1, C1.1 |
| `sec_16_pii_naming_heuristics` | Data Classification | 3.2 | §164.308(a)(1)(ii)(A) | CC6.1, C1.1 |

### Network & Exposure

| Script (all engines) | CIS | PCI DSS v4.0 | HIPAA Security Rule | SOC 2 TSC |
|---|---|---|---|---|
| `sec_08_network_exposure` | Network Config | 1.3, 1.4 | §164.312(e)(1) | CC6.6, CC6.7 |
| `sec_15_external_integrations` | Third-Party | 12.8 | §164.308(b)(1) | CC9.2 |

### Dangerous Features

| Script (all engines) | CIS | PCI DSS v4.0 | HIPAA Security Rule | SOC 2 TSC |
|---|---|---|---|---|
| `sec_10_dangerous_objects` | Hardening | 6.3.2, 2.2 | §164.308(a)(5)(ii)(B) | CC6.1, CC6.8 |
| `sec_17_deprecated_features` | Hardening | 2.2 | §164.308(a)(5)(ii)(B) | CC7.1 |

### Backup & Recovery

| Script (all engines) | CIS | PCI DSS v4.0 | HIPAA Security Rule | SOC 2 TSC |
|---|---|---|---|---|
| `sec_14_backup_security` | Backup | 9.4 | §164.308(a)(7)(ii)(A), §164.310(d)(2)(iv) | A1.2, A1.3 |

### Performance & Availability (SOC 2 Availability criterion)

| Script (all engines) | CIS | PCI DSS v4.0 | HIPAA Security Rule | SOC 2 TSC |
|---|---|---|---|---|
| `perf_01_top_queries` | — | — | — | A1.1, A1.2 |
| `perf_02_blocking_and_locks` | — | — | — | A1.1, A1.2 |
| `perf_03_sessions_and_connections` | — | 10.2 | — | A1.1 |
| `perf_04_cache_and_memory` | — | — | — | A1.2 |
| `perf_05_io_hotspots` | — | — | — | A1.2 |
| `perf_06_index_health` | — | — | — | A1.2 |
| `perf_07_maintenance_health` | — | — | — | A1.2 |
| `perf_08_replication_lag` | — | — | §164.308(a)(7)(ii)(A) | A1.2, A1.3 |
| `perf_09_config_drift` | Config Baseline | 2.2 | §164.308(a)(1)(ii)(B) | CC7.1, A1.2 |
| `perf_10_replication_topology` | — | — | §164.308(a)(7)(ii)(A) | A1.2, A1.3 |
| `perf_11_bloat_estimation` | — | — | — | A1.2 |
| `perf_12_sequential_scans` | — | — | — | A1.2 |
| `perf_13_deadlock_history` | — | — | — | A1.2 |
| `perf_14_checkpoint_bgwriter` | — | — | — | A1.2 |
| `perf_15_capacity_and_growth` | — | — | — | A1.2 |
| `perf_16_plan_instability` | — | — | — | A1.2 |
| `perf_17_skewed_data` | — | — | — | A1.2 |
| `perf_18_forecast_inputs` | — | — | — | A1.2 |
| `perf_19_storage_topology` | — | — | §164.308(a)(7)(i) | A1.2, A1.3 |
| `perf_20_workload_management` | — | — | — | A1.1, A1.2 |

## Frameworks quick reference

- **CIS Benchmarks** — engine-specific hardening guides. Pick the correct
  version: CIS PostgreSQL 15/16, CIS MySQL 8.0, CIS SQL Server 2019/2022.
- **PCI DSS v4.0** — Payment Card Industry, March 2024. Requirements above
  use the v4.0 numbering (some renumbered vs. v3.2.1).
- **HIPAA Security Rule** — 45 CFR Part 164 Subpart C. Database evidence
  primarily supports the Administrative (§164.308) and Technical
  (§164.312) Safeguards.
- **SOC 2 TSC** — Trust Services Criteria (AICPA 2017, revised 2022).
  CC = Common Criteria, A = Availability, C = Confidentiality.

## Caveats

- **Mapping is not certification.** These scripts produce evidence; they do
  not attest compliance. An auditor must review the output against your
  documented policy.
- **Some controls require out-of-band evidence** that no SQL script can
  provide — e.g., background checks for privileged users, physical
  security of the server room, change-management ticket trails.
- **Control numbering evolves.** Recheck PCI DSS / CIS references against
  the version in force at audit time.
