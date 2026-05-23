# Error handling patterns

Real-world recovery patterns for `nlink::Error`. Every nlink method
returns `Result<T, nlink::Error>`; the variants are
[non-exhaustive][non_exhaustive], and discrimination uses `is_*()`
predicates rather than direct variant matching — see
[`crates/nlink/src/netlink/error.rs`][error-rs]. This recipe covers
the patterns most production consumers reach for in their first
month.

[non_exhaustive]: https://doc.rust-lang.org/reference/attributes/type_system.html#the-non_exhaustive-attribute
[error-rs]: ../../crates/nlink/src/netlink/error.rs

## When to use this

- You're handling errors from a long-running consumer (a daemon, an
  exporter, a CNI plugin) and need to decide which errors are
  transient vs fatal.
- You want to surface kernel diagnostics to your users (the kernel
  has more to say than the bare errno).
- You're getting `Err(...)` and unsure whether to retry, fail, or
  log-and-continue.

## Idiom: predicate dispatch, not variant match

`Error` is `#[non_exhaustive]` and gains new variants per release.
**Always** dispatch on `is_*()` predicates, with a final `_` arm or
`return Err(other)`:

```rust,no_run
use nlink::{Connection, Route, TcHandle};

# async fn run(conn: &Connection<Route>) -> nlink::Result<()> {
match conn.del_qdisc("eth0", TcHandle::ROOT).await {
    Ok(()) => {}
    Err(e) if e.is_not_found() => {
        // Idempotent delete — already gone, success.
        tracing::debug!("qdisc already absent; nothing to do");
    }
    Err(e) if e.is_busy() => {
        // EBUSY → kernel is mid-operation; retry once after a
        // short backoff. See "EAGAIN / ENOBUFS — kernel pressure"
        // below.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.del_qdisc("eth0", TcHandle::ROOT).await?;
    }
    Err(e) if e.is_permission_denied() => {
        // EPERM → CAP_NET_ADMIN missing. Hard fail — code can't
        // self-elevate.
        return Err(e);
    }
    Err(e) => return Err(e),
}
# Ok(())
# }
```

Predicate list (see [`error.rs`][error-rs] for the full set):

- `is_not_found` (ENOENT, plus typed `QdiscNotFound` etc.)
- `is_already_exists` (EEXIST)
- `is_busy` (EBUSY)
- `is_invalid_argument` (EINVAL)
- `is_no_device` (ENODEV)
- `is_permission_denied` (EPERM, EACCES)
- `is_network_unreachable` (ENETUNREACH)
- `is_timeout` (ETIMEDOUT plus the synthetic `Error::Timeout`)
- `is_address_in_use` (EADDRINUSE)
- `is_no_buffer_space` (ENOBUFS — multicast overflow)
- `is_try_again` (EAGAIN)
- `is_not_supported` (EOPNOTSUPP / ENOTSUP)
- `is_namespace_restore_failed` — thread stuck in foreign netns
  after a `new_in_namespace` socket creation; **not** retryable

## EAGAIN / ENOBUFS — kernel pressure

The kernel returns these when its internal queues are saturated.
Recovery is bounded retry with backoff. **Always cap the retry
count**; an infinite retry hides real bugs.

```rust,no_run
use std::time::Duration;
use nlink::{Connection, Route};

async fn with_retry<T, F, Fut>(mut op: F, label: &str) -> nlink::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = nlink::Result<T>>,
{
    let mut delay = Duration::from_millis(10);
    for attempt in 0..5 {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if e.is_try_again() || e.is_no_buffer_space() => {
                tracing::warn!(%attempt, "{label}: transient pressure ({e}); retrying in {delay:?}");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(1));
            }
            Err(other) => return Err(other),
        }
    }
    Err(nlink::Error::Timeout)
}
```

For multicast subscribers, ENOBUFS specifically means the kernel
dropped events because your consumer fell behind. Plan 151's
`events_with_resync()` (0.16) handles this transparently — see
that recipe when it ships.

## Idempotent add / del with `NLM_F_EXCL`

Most `add_*` methods set `NLM_F_CREATE | NLM_F_EXCL`, which makes
the kernel return EEXIST if the resource already exists. This is
deliberate — silent overwrite is rarely what callers want. For an
idempotent "create-if-missing" pattern:

```rust,no_run
# async fn run(conn: &nlink::Connection<nlink::Route>) -> nlink::Result<()> {
# use nlink::netlink::link::DummyLink;
match conn.add_link(DummyLink::new("test0")).await {
    Ok(()) => tracing::info!("created"),
    Err(e) if e.is_already_exists() => tracing::info!("already present"),
    Err(e) => return Err(e),
}
# Ok(())
# }
```

For `del_*`, the symmetric pattern treats `is_not_found()` as
success:

```rust,no_run
# async fn run(conn: &nlink::Connection<nlink::Route>) -> nlink::Result<()> {
match conn.del_link_by_name("test0").await {
    Ok(()) | Err(_) if conn.del_link_by_name("test0")
        .await
        .err()
        .is_some_and(|e| e.is_not_found()) => Ok(()),
    Ok(()) => Ok(()),
    Err(e) if e.is_not_found() => Ok(()),
    Err(e) => Err(e),
}?;
# Ok(())
# }
```

Or use the [`tc_recipe::ReconcileReport`][reconcile] pattern from
the high-level helpers, which bakes the idempotency in.

[reconcile]: https://docs.rs/nlink/latest/nlink/struct.ReconcileReport.html

## XFRM SA/SP conflicts

XFRM has its own EEXIST shape: the kernel matches on `(daddr,
spi, proto)` for SAs and `(selector, dir)` for SPs. Two patterns:

**Replace** when you control the SA and want to rotate keys:

```rust,no_run
# async fn run(conn: &nlink::Connection<nlink::netlink::protocol::Xfrm>) -> nlink::Result<()> {
# let new_sa = unimplemented!();
// `update_sa` replaces an existing SA in place — no
// delete-then-add window where traffic would drop.
conn.update_sa(&new_sa).await?;
# Ok(())
# }
```

**Delete-then-add** when the existing SA is foreign (installed by
another process) and you need to take it over:

```rust,no_run
# async fn run(conn: &nlink::Connection<nlink::netlink::protocol::Xfrm>) -> nlink::Result<()> {
# let dst = unimplemented!();
# let spi = 0;
# let proto = 50;
# let new_sa = unimplemented!();
// Tolerate "wasn't there" so the routine is idempotent.
match conn.del_sa(&dst, spi, proto).await {
    Ok(()) | Err(_) => {}
}
conn.add_sa(&new_sa).await?;
# Ok(())
# }
```

The `update_sa` path is strictly preferable when applicable — it
preserves the SA's anti-replay state. Document which path your
control plane uses.

## Namespace cleanup on error paths

`LabNamespace` (feature `lab`) cleans itself up on drop, including
when a setup step fails mid-way:

```rust,no_run
# #[cfg(feature = "lab")]
# async fn run() -> nlink::Result<()> {
use nlink::lab::LabNamespace;

let ns = LabNamespace::new("recipe-demo")?;
// Any `?` here that errors out still drops `ns` cleanly, which
// removes the namespace.
let conn = ns.connection()?;
conn.add_link(nlink::netlink::link::DummyLink::new("demo0")).await?;
// ... rest of setup ...
# Ok(())
# }
```

For hand-rolled `unshare(CLONE_NEWNET)` consumers, the same
discipline applies via an explicit guard. **Never** issue a bare
`unshare()` and trust later cleanup — `Drop` is the only reliable
unwind path under `?`.

If the cleanup itself fails (e.g., the netns binding was already
torn down by another process), `LabNamespace::drop` emits a
`tracing::warn!` event and continues — silent stderr is no longer
used as of 0.16. See `is_namespace_restore_failed()` for the
analogous on-construction failure mode.

## Cross-process / cross-fork pitfalls

Holding a `Connection<P>` across `fork(2)` is **unsupported**.
The netlink socket fd is shared (so messages interleave) and
sequence numbers race (so replies match the wrong request). For
multi-process designs:

- Open the `Connection` per-process **after** fork.
- If you must hand a configuration across fork boundaries, send
  only the typed configs (`NetworkConfig`, `HtbQdiscConfig`,
  etc.); reconstruct the Connection on the other side.

Same advice for execve-style child processes: don't inherit the
netlink fd via `CLOEXEC`-cleared sockets unless you've thought
through the sequence-number contention story.

## Cancellation safety in async

Most `Connection<P>` methods are cancel-safe in the standard
tokio sense: if you `tokio::select!` on them and the other arm
wins, the netlink socket state stays consistent (the in-flight
request's reply will be ignored on the next `recv_msg` because
its sequence number is stale).

The exceptions:

1. **Multicast subscription state** survives cancellation —
   `subscribe()` already mutated the socket. If you cancel
   mid-`subscribe`, the membership may be partially applied;
   call `subscribe` again with the desired groups to converge.
2. **`Transaction::commit`** (nftables) is **not** cancel-safe in
   the rollback sense — once the syscall returns, the kernel has
   either committed or rolled back the batch as a unit, but if
   the future is cancelled before the commit syscall executes,
   the batch is silently abandoned. Idempotency on retry is the
   caller's responsibility.

## See also

- [`crates/nlink/src/netlink/error.rs`][error-rs] — full `Error`
  enum + every `is_*()` predicate
- [Connections & namespaces section of CLAUDE.md][claude-md] —
  the namespace-safety story relevant to
  `is_namespace_restore_failed`
- [`docs.rs/nlink/latest/nlink/struct.Error.html`][error-docs] —
  rendered API docs

[claude-md]: ../../CLAUDE.md
[error-docs]: https://docs.rs/nlink/latest/nlink/struct.Error.html
