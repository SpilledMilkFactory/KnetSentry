<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Reproducible Workload Profiles

**Issue:** M0.5. **Status:** benchmark design; fixture generation and tooling
are future implementation work. No production network traffic is authorized.

## 1. Reference environment

- Platform: Ubuntu 26.04 AMD64, with kernel, GCC/CMake/Qt versions and package
  hashes captured at test time; do not substitute a different OS silently.
- Hardware: inventory actual CPU model, logical cores, RAM, SSD model,
  filesystem, mount options, power profile, and network/NIC speed. Record
  virtualization and NUMA information when present.
- Roles: at least a manager, an unprivileged Qt GUI, and an approved agentless
  source (gateway-export emulator or passive replay). Optional endpoint-agent
  results are additional; they cannot replace the agentless qualification.
- Workload datasets: sanitized/deterministic synthetic events with fixed seeds
  and a documented distribution of source protocols, valid/invalid records,
  record sizes (512 B, 2 KiB, 4 KiB), duplicate rates and timestamps.
- Network replay: isolated namespace, offline pcap or lab mirror/tap with
  explicit permission and independent packet counts. No real Internet probes,
  unauthorized LAN scanning, or active replay onto production networks.
- Timekeeping: record NTP/chrony state and source clock offsets; only compare
  cross-host timestamps within a measured and reported uncertainty bound.

## 2. Workload definitions

| ID | Scenario | Workload / duration | What is independently counted |
| --- | --- | --- | --- |
| `W-00` | Idle control | 10 min warm-up plus 10 min idle, feeds and AI disabled | Baseline CPU, RSS, filesystem, system pressure |
| `W-01` | Sustained ingest | 100 accepted EPS x 60 min = 360,000; 10 reporting sources with >=1 agentless source; diverse valid/invalid records | Submitted, received, accepted, durable, indexed, rejected, duplicate and alerts |
| `W-02` | Ingest burst | 1,000 accepted EPS x 60 s = 60,000 while nominal 100 EPS continues before and afterward; drain for up to 5 min | Queue peak, durable counts, latency tails and time-to-drain |
| `W-03` | Agentless sustained capture | 2,000 delivered PPS x 30 min = 3,600,000 reference packets through isolated capture path | Generator/NIC, broker, parser, flow/event counts and all drop counters |
| `W-04` | Agentless burst capture | 10,000 delivered PPS x 60 s = 600,000 reference packets in isolation | Same stage counters plus peak buffers and capture drop fraction |
| `W-05` | Read and GUI concurrency | Seven-day-equivalent indexed dataset; concurrent W-01 ingest, 5 query clients, 1 live Qt GUI for 30 min | Query percentiles, UI interactions, frame intervals, errors, memory |
| `W-06` | Outage, restart and storage | One source 10 EPS disconnected 30 min (18,000 records), manager crash/restart, disk and restore fault fixtures | Acknowledged IDs, replay IDs, losses, alerts, recovery durations |
| `W-07` | Offline operations | 30 min W-01-like local ingest/detection with Internet, feeds, and AI disabled | Feature continuity, denied outbound attempts, event and alert counts |

The `W-01` ten-source mix may include gateway exports, passive sensor streams,
optional host agents, and synthetic records representing each. Every claimed
source must have an explicit trust and observability status. **No device agent
is required** for the printer/doorbell fixture.

| `W-08` | Configurable two-volume placement | Select a separately mounted local raw store, distinct local SQLite index store; W-01 ingest + W-05 queries for 30 min | Raw segment committed counts, index lag, raw/index disk bytes, permission and fsync failures |
| `W-09` | Raw volume fault and migration | During 10 EPS agentless input unmount/remount or replace simulated external store, fill quota/read-only, attempt new target and rollback | Mount identity, rejected acknowledgments, no root-disk fallback, spool usage, integrity after resumption |

The GUI folder picker shall use a desktop-integrated file-selection flow (Qt Quick Dialogs or a native Qt dialog, depending on KDE/GNOME compatibility testing), but the unprivileged GUI **does not** confer manager write permission. Test the effective daemon identity and mount namespace. External drives are supported only when mounted to an explicitly approved local filesystem path; unsupported network mounts must be rejected pending separate qualification.

## 3. Record and packet generation

Every synthetic run must record a generator version, fixed seed, fixture
SHA-256, event-size histogram, traffic mix, capture snaplen, offloading
configuration, transport, number of sources, and exact generator command.
A standalone generator must use monotonic counters and a separate sink-side
counter; its output volume is not evidence of arrival or durable persistence.
Packet tests must measure delivered traffic independently: a nominal sender
rate alone does not prove packet reception. If source hardware cannot sustain
the offered rate, mark `INVALID_RUN`, not `FAIL` for the sensor.

Malformed records, IPv4/IPv6, non-ASCII text, duplicate IDs, clock drift and
agentless asset ambiguity should be represented in a documented fixture mix.
Do not make a performance test pass by disabling authentication, rate limits,
privacy settings, monitoring coverage, or durable persistence.

## 4. Run isolation and repeatability

1. Freeze code commit, release configuration, dependency versions, hardware
   profile and relevant runtime settings; ensure sufficient storage before run.
2. Capture idle `W-00`, filesystem free space, thermal/power state and system
   pressure; warm caches under a reported protocol before timed measurement.
3. Run each performance scenario at least **three** independent times after
   reset/rebuild of the test dataset; report **all** iterations, not just best.
4. Record generator-side and every receiving-stage counters, wall time,
   monotonic durations, CPU/RSS/PSI, disk I/O and per-stage loss/duplicates.
5. Compare results using a declared percentile algorithm and no cherry-picked
   intervals; if sampling or counters are unavailable, report `INCOMPLETE`.
6. Scrub test artifacts before sharing; use synthetic or consented data only.

See [benchmark plan](BENCHMARK_PLAN.md) for acceptance and
[storage model](RESOURCE_CAPACITY_MODEL.md) for seven-day dataset sizing.
