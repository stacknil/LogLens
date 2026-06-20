# Performance Envelope

This document records a local performance envelope for LogLens. It is a
reviewer aid, not a throughput guarantee or service-level objective.

The benchmark measures the offline CLI path:

- parse sanitized `syslog_legacy` input
- normalize events and parser warnings
- run the default detector configuration
- write `report.md` and `report.json`

CSV export was not enabled.

## Benchmark Platform

| Field | Value |
| --- | --- |
| Date | 2026-06-21 |
| OS | Microsoft Windows 11, version `10.0.26200`, build `26200` |
| CPU | AMD Ryzen 9 7940HX with Radeon Graphics |
| Logical processors | 32 |
| RAM | 31.2 GB |
| Shell | PowerShell 7.5.5 |
| Build | CMake Release build |
| Executable | `build\Release\loglens.exe` |

## Workload Shape

The input corpus was generated locally under `build/performance-envelope/`.
Generated files are not committed.

The synthetic input uses sanitized syslog-style records only:

- `bench-host-*` hostnames
- documentation-range `203.0.113.x` source IPs
- synthetic `userNNN` usernames
- timestamps one second apart, starting at `2026-03-10 00:00:00`
- an eight-line cycle of SSH failure, SSH success, sudo, PAM auth failure,
  unsupported SSH preauth close, unsupported SSH timeout, session-opened, and
  `su` failure evidence

The resulting report shape is intentionally mixed:

- 75% parsed lines
- 25% parser warnings
- stable parser warning buckets for unsupported SSH preauth and timeout lines
- 50 top-level findings in each measured size

This shape exercises parser coverage telemetry and report writing without using
real authentication data.

## Method

Command shape:

```powershell
build\Release\loglens.exe --mode syslog --year 2026 <input.log> <output-dir>
```

For each line count:

- one warmup run was excluded from the table
- five measured runs were recorded
- elapsed time is wall-clock process time
- peak memory is the maximum observed process working set sampled by the
  benchmark harness
- input generation time is excluded

## Results

| Input lines | Parsed lines | Parser warnings | Findings | Median elapsed | Elapsed range | Peak working set |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 750 | 250 | 50 | 44.66 ms | 44.47-64.96 ms | 3.10 MB |
| 10,000 | 7,500 | 2,500 | 50 | 104.01 ms | 91.36-107.15 ms | 13.82 MB |
| 100,000 | 75,000 | 25,000 | 50 | 635.69 ms | 588.39-796.45 ms | 99.77 MB |

## Interpretation

The measured envelope is comfortably interactive for 100k-line local review on
this machine. The largest run completed in less than one second and stayed under
100 MB peak working set.

The numbers should be read as a regression reference for this input shape. They
are not a claim about all Linux authentication logs. Runtime and memory can
change with:

- larger finding evidence windows
- substantially different unsupported-line ratios
- CSV export
- slower storage
- debug builds
- background load on the host

Parser observability remains part of the measured path: unsupported lines are
reported as warnings and telemetry rather than being silently dropped.
