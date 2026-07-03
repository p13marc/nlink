# Per-process TCP bandwidth (unprivileged)

Answer "which process is eating my uplink?" with nothing but
`NETLINK_SOCK_DIAG` polling and `/proc` — no eBPF, no root (for your
own processes), no packet capture. This is the bmon/nethogs-style
fallback built from three sockdiag utilities that ship in 0.24:
kernel-side dump filtering, cookie-keyed rate tracking, and
socket→process attribution.

## When to use this

- A metrics exporter or TUI that reports per-socket / per-process /
  per-cgroup TCP throughput on an interval.
- Container observability: join `InetSocket.cgroup_id` back to
  `system.slice/…` / pod cgroup paths without a /proc scan per socket.
- Anywhere eBPF is unavailable (locked-down kernels, unprivileged
  containers) and polling resolution (~1s) is acceptable.

**Constraints to accept up front** (architectural, not nlink gaps):

- **TCP only.** `tcp_info` carries cumulative `bytes_acked` /
  `bytes_received` (4.1+) and `bytes_sent` / `bytes_retrans` (4.19+).
  **UDP has no per-socket cumulative byte counters in the kernel** —
  `udp_diag` reports only instantaneous queue depths, which must
  never be diffed for a rate. Per-process UDP bandwidth via sock_diag
  is impossible; use eBPF.
- **Goodput, not wire throughput.** The counters measure acknowledged
  application payload — no headers, no retransmitted bytes. Don't
  compare against interface counters; retransmission overhead is
  visible separately as `SocketRate::retrans_ratio`.
- **Short flows are invisible.** A socket opened and closed between
  two polls never appears. Kernel 6.5+ BPF socket iterators
  (`tcplife`/`tcptop`) are the event-driven successor.

## High-level approach

Once per tick:

1. **Dump** TCP sockets with `with_tcp_info()` (the byte counters ride
   in `tcp_info`), optionally pre-filtered kernel-side with a
   `FilterExpr` so non-matching sockets never cross into userspace.
2. **Ingest** the snapshot into a `SocketRateTracker`. It keys deltas
   by the kernel **socket cookie** — never the inode, which gets
   reused across a poll interval and would silently corrupt deltas —
   and yields `{cookie, tx_goodput_bps, rx_goodput_bps,
   retrans_ratio}` for every socket seen in two consecutive dumps.
3. **Attribute**: one `SocketOwnerMap::scan()` per tick (a single
   amortized `/proc` walk) joins inodes to `(pid, start_time, comm)` —
   the `(pid, start_time)` pair survives PID reuse. One
   `CgroupPathMap::scan()` (usually once at startup) inverts the
   already-exposed `cgroup_id` to its cgroupfs path.

## Code

```rust,no_run
use std::{collections::HashMap, time::{Duration, Instant}};
use nlink::netlink::{Connection, SockDiag};
use nlink::sockdiag::{
    CgroupPathMap, FilterExpr, SocketFilter, SocketOwnerMap, SocketRateTracker,
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<SockDiag>::new()?;
    let mut tracker = SocketRateTracker::new();
    // cgroup topology is stable enough to scan once.
    let cgroups = CgroupPathMap::scan();

    // Optional kernel-side pre-filter: established sockets only.
    // Pure-state predicates hoist into the request header; ports and
    // addresses compile to INET_DIAG_REQ_BYTECODE (#163).
    let expr = FilterExpr::parse("state established")
        .map_err(nlink::Error::InvalidMessage)?;

    loop {
        let snapshot = conn
            .query(&SocketFilter::tcp().with_tcp_info().filter_expr(expr.clone()).build())
            .await?;
        let inet: Vec<_> = snapshot.iter().filter_map(|s| s.as_inet()).collect();

        // cookie → join keys, captured per snapshot.
        let keys: HashMap<u64, (u32, Option<u64>)> =
            inet.iter().map(|s| (s.cookie, (s.inode, s.cgroup_id))).collect();

        let rates = tracker.ingest(inet.iter().copied(), Instant::now());

        // One /proc walk per tick, amortized over every socket.
        let owners = SocketOwnerMap::scan();
        for r in &rates {
            let (inode, cgroup_id) = keys[&r.cookie];
            let who = owners.resolve(inode).first()
                .map(|p| format!("{} (pid {}, start {})", p.comm, p.pid, p.start_time))
                .unwrap_or_else(|| "?".into());
            let unit = cgroup_id
                .and_then(|id| cgroups.resolve_relative(id))
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            println!(
                "{who:<40} {unit:<40} tx {:>10} B/s rx {:>10} B/s retr {:.2}%",
                r.tx_goodput_bps, r.rx_goodput_bps, r.retrans_ratio * 100.0,
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
```

Runnable version: `cargo run -p nlink --features sockdiag --example
sockdiag_rate_top` (bounded to a few rounds instead of looping).

## Caveats

- **Privileges scope attribution, not rates.** Rates work for every
  socket unprivileged. `/proc/<pid>/fd` for *other* users' processes
  is unreadable without root — those sockets resolve to no owner,
  matching `ss -p` behaviour. Run the scanner as root for
  whole-system attribution.
- **First ingest is a baseline** — the tracker yields rates only for
  sockets seen in two consecutive dumps.
- **Counter regressions re-baseline.** If a cookie's counters ever go
  backwards (cookie reuse would require a kernel anomaly), the sample
  is dropped rather than reported as a bogus huge rate.
- **Eviction is generation-based**: cookies absent for 3 consecutive
  ingests (configurable via `with_evict_after`) are dropped, so the
  tracker's memory tracks the live socket set.
- **cgroup v2 only** for the path join — the kernel's `cgroup_id` is
  the cgroupfs inode on the unified hierarchy; v1 IDs don't
  correspond and every lookup misses.
- On kernels older than 4.19, `bytes_sent`/`bytes_retrans` read 0, so
  `retrans_ratio` is 0; the goodput fields (4.1+) still work.

## See also

- [`cgroup-classification`](cgroup-classification.md) — the shaping
  counterpart (classify traffic *by* cgroup with TC).
- `crates/nlink/examples/sockdiag/socket_owners.rs` — attribution
  only, single snapshot.
- `crates/nlink/examples/sockdiag/filter_expr.rs` — the kernel-side
  expression filtering on its own, including `compile_filter`
  introspection and `CcInfo` (BBR/DCTCP/vegas) display.
- Module docs: `nlink::sockdiag` (constraints),
  `nlink::sockdiag::rate`, `nlink::sockdiag::procmap`,
  `nlink::sockdiag::bytecode`.
