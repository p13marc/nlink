# Connection pool

Hold a bounded set of `Connection<P>` and round-robin requests
across them — the right answer when you'd otherwise hand-roll
multiple connections to issue parallel work.

## When to use this

- A long-running consumer that issues parallel dumps or writes
  from many tasks (a metrics exporter scraping N namespaces; a
  CNI plugin orchestrating dozens of pods; a control plane
  watching link-state across all of `/var/run/netns/*`).
- You want a single shared abstraction rather than fork-per-task
  connection construction.
- You want async-aware backpressure (acquires wait when the pool
  is exhausted; they don't burn CPU).

If you're issuing one request at a time from a single task, a
plain `Connection<P>` is the right answer — no pool needed.

## High-level approach

`ConnectionPool<P>` wraps a `tokio::sync::mpsc::Sender + Receiver`
whose capacity matches the pool size. `acquire().await` is `recv`
on the channel (blocks when empty); the returned
`PooledConnection<'p, P>` returns the connection to the pool on
drop via `try_send`. Each pooled connection retains the
**single-flight** invariant — only one request in-flight per
connection at a time. Concurrency comes from holding multiple
connections, not from multiplexing one.

This is the partial alternative to `neli`'s `NlRouter`-style
multi-request-per-socket fanout (deferred to 0.17; see master
plan §4 item 6). For the documented use cases, the pool gives
≥80% of the throughput benefit at <10% of the implementation
risk.

## Code

```rust,no_run
use std::sync::Arc;
use std::time::Duration;
use nlink::{ConnectionPoolBuilder, Route};

# async fn run() -> nlink::Result<()> {
let pool = Arc::new(
    ConnectionPoolBuilder::<Route>::new()
        .size(8)
        .acquire_timeout(Duration::from_secs(2))
        .build()
        .await?,
);

// Parallel link dumps across the pool:
let mut joins = Vec::new();
for ns_idx in 0..16 {
    let pool = Arc::clone(&pool);
    joins.push(tokio::spawn(async move {
        let conn = pool.acquire().await?;
        tracing::info!("task {ns_idx} got a connection");
        conn.get_links().await
    }));
}
for j in joins {
    let _ = j.await;
}
# Ok(())
# }
```

## Per-namespace pools

For CNI-plugin-shaped consumers watching N namespaces: one
`Arc<ConnectionPool<Route>>` per namespace.

```rust,no_run
use std::sync::Arc;
use nlink::{ConnectionPool, Route};

# async fn run(ns_names: &[&str]) -> nlink::Result<()> {
let pools: Vec<Arc<ConnectionPool<Route>>> = {
    let mut ps = Vec::with_capacity(ns_names.len());
    for ns in ns_names {
        ps.push(Arc::new(ConnectionPool::<Route>::for_namespace(*ns, 4).await?));
    }
    ps
};

// Concurrent dumps across all namespaces:
let dumps = pools.iter().enumerate().map(|(i, pool)| {
    let pool = Arc::clone(pool);
    tokio::spawn(async move {
        let conn = pool.acquire().await?;
        (i, conn.get_links().await)
    })
});
// ... await dumps and aggregate ...
# Ok(())
# }
```

## Sizing guidance

- **I/O-bound bursty workload** (a Prometheus exporter scraping
  every 15s): pool size = `2 × num_cpus`.
- **Steady-state workload**: pool size = max-expected-concurrent
  requests.
- **Memory cost**: each pooled `Connection` owns one netlink
  socket fd. Cheap. With the `syscall_batch` feature (Plan 158,
  0.16+) each connection lazily allocates ~1 MB of recv buffers
  on first batched recv — keep that in mind for pools sized in
  the hundreds.

## Caveats

- **Single-flight per connection**. Two tasks holding two
  different `PooledConnection`s can issue requests concurrently;
  two tasks sharing one would race the socket. The pool's design
  prevents the latter: `acquire` hands out exclusive ownership
  until drop.
- **No auto-rebuild on dead connections** in 0.16. If a pooled
  socket dies (rare — netlink sockets are surprisingly durable),
  the pool will hand out the dead connection on the next
  acquire; the operation will fail. Call
  [`PooledConnection::invalidate`] to drop instead of returning
  to the pool. The "rebuild on next acquire" feature is on the
  0.17 roadmap.
- **Pool of size 0 is clamped to 1**. A pool of 0 would deadlock
  on first acquire; the builder silently clamps.
- **Drop semantics**: dropping the last `Arc<ConnectionPool>`
  closes all sockets in pool order. Outstanding
  `PooledConnection` guards stay valid until their own drop —
  their `Connection` is owned, not borrowed.

## See also

- [`crate::netlink::pool` module docs][pool-docs] — full API
  details
- [Plan 159][plan-159] — design history and the 0.17 roadmap
  (smart health-checking, adaptive sizing, GENL family-cache
  sharing)
- [`docs/recipes/events-with-resync.md`][resync] — `dump_conn`
  for Plan 151's resync helper naturally comes from a pool
- [`docs/recipes/error-handling-patterns.md`][errors] — how to
  dispatch on `is_pool_exhausted` / `is_pool_closed`

[pool-docs]: https://docs.rs/nlink/latest/nlink/netlink/pool/index.html
[plan-159]: ../../plans/159-0.16-connection-pool-plan.md
[resync]: events-with-resync.md
[errors]: error-handling-patterns.md
