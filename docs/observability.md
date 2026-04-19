# Observability

`nlink` emits structured `tracing` spans on its public API surface.
This is purely additive: spans cost a single relaxed atomic load when
no subscriber is attached (the standard `tracing` crate guarantee), so
the instrumentation has no measurable runtime cost in production until
a consumer wires up a subscriber.

This document describes what's instrumented, what level each span
sits at, and how to configure a subscriber to surface the data.

## Quick start

Add `tracing-subscriber` to your binary's `Cargo.toml`:

```toml
[dependencies]
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

Initialize a subscriber early in `main`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // ... your code ...
}
```

Then run with `RUST_LOG` set to see spans:

```bash
# All nlink debug-level spans
RUST_LOG=nlink=debug cargo run

# Only TC operations
RUST_LOG=nlink::netlink::tc=debug cargo run

# Only the recipe helpers (high-level summary spans)
RUST_LOG=nlink::netlink::impair=info,nlink::netlink::ratelimit=info cargo run

# Everything including per-message TRACE
RUST_LOG=nlink=trace cargo run
```

## Level conventions

| Level   | What goes here                                                                   |
| ------- | -------------------------------------------------------------------------------- |
| `ERROR` | Unrecoverable: socket closed unexpectedly. Almost never.                         |
| `WARN`  | Kernel returned a non-zero `errno` for a request or ack.                         |
| `INFO`  | Connection lifecycle (open / namespace / subscribe); GENL family resolution; recipe `apply` / `clear` / `remove`. |
| `DEBUG` | Public API entry — every Connection method (qdisc, class, filter, link, addr, route, neighbor, FDB, etc.). |
| `TRACE` | Each netlink request / ack / dump cycle (with sequence numbers and response counts); each multicast event batch parsed. |

## What's instrumented

### Connection lifecycle (INFO)

- `Connection::<P>::new()` — protocol type name in the `protocol` field.
- `Connection::<P>::new_in_namespace(ns_fd)` — adds the `ns_fd` field.
- `Connection::<P>::new_in_namespace_path(ns_path)` — adds the `ns_path` field as a Display.
- `Connection::<Route>::subscribe(groups)` — lists the multicast `groups` subscribed.

### Netlink request / ack / dump (TRACE)

The internal send/recv loops carry the kernel-assigned `seq` on every
span; on dump completion the span records the `responses` count. On
a non-zero kernel errno an additional `WARN`-level event fires with
the errno field attached, so users see "kernel returned error" without
having to parse the `Error` `Display` output.

### Public Connection methods (DEBUG)

Every `pub async fn` on `Connection<Route>`, `Connection<Generic>`,
and the GENL protocol-specific `Connection<*>` types
(`Wireguard`, `Macsec`, `Mptcp`, `Ethtool`, `Nl80211`, `Devlink`,
`Nftables`, `Xfrm`, `Netfilter`, `Audit`, `Connector`, `KobjectUevent`,
`FibLookup`, `SELinux`) carries an `#[instrument(level = "debug",
skip_all, fields(method = "..."))]`. The `method` field is the function
name as a string, so you can filter:

```bash
RUST_LOG="nlink[method=add_qdisc]=debug" cargo run
```

`skip_all` is used because not every parameter type implements
`Display`/`Debug` — the `method` field gives the handle to filter on
without burning fmt traits into every TC config struct.

### GENL family resolution (INFO once per family)

`Connection::<Generic>::get_family(name)` carries `family`, `id`, and
`cached` fields. Users see exactly which families are looked up and
when the cache misses (the kernel round-trip happens once per process
per family).

### Batch operations (DEBUG)

`Batch::execute()` records the `ops` field (operation count). For a
1000-route batch you'll see one DEBUG span at the start and TRACE
spans for each chunk's underlying `send_dump_inner` call.

### Multicast event delivery (TRACE)

Both `EventSubscription::poll_next` and `OwnedEventStream::poll_next`
emit a TRACE event each time a netlink frame is received and parsed,
with the `protocol` (type name) and `events` (parsed event count)
fields. Useful for debugging "I'm subscribed but not seeing events" —
you can confirm whether the kernel is sending data at all.

### Recipe helpers (INFO)

The high-level recipe helpers carry one span per top-level call:

- `RateLimiter::apply(...)` and `RateLimiter::remove(...)` — `dev`,
  `egress`, `ingress` (booleans for which directions are configured).
- `PerHostLimiter::apply(...)` and `PerHostLimiter::remove(...)` —
  `dev`, `rules`.
- `PerPeerImpairer::apply(...)` and `PerPeerImpairer::clear(...)` —
  `target` (interface ref), `rules`.

These are the most likely operations to fail in production because
they synthesize a multi-step TC tree (HTB qdisc → root class → per-rule
classes → per-class leaves → per-class filters). The INFO span gives
you a single line summarizing what the helper attempted; the underlying
DEBUG spans on the individual `add_qdisc` / `add_class` /
`add_filter` calls show you exactly which step fired which kernel
operation.

## Common queries

Trace one full `PerPeerImpairer::apply` in detail:

```bash
RUST_LOG="nlink::netlink::impair=info,nlink[method=add_qdisc]=debug,nlink[method=add_class_config]=debug,nlink[method=add_filter]=debug,nlink::netlink::connection[send_ack_inner]=trace"
```

See every kernel error returned to your process (useful when something
is silently broken):

```bash
RUST_LOG="nlink::netlink::connection=warn"
```

Watch every multicast event delivered to your subscriber:

```bash
RUST_LOG="nlink::netlink::stream=trace"
```

## Why not log macros?

`tracing` is a strict superset of `log` for our use case: spans nest,
fields are structured (so a future `tracing-opentelemetry` integration
gets useful telemetry), and the `method` field works as both a log
prefix and a filterable predicate. The `tracing` macros also expand to
nothing when no subscriber is attached, whereas `log` macros allocate
a `Record` regardless of whether a sink is configured.

## Why not feature-gate?

`tracing` is gated behind no feature flag because gating it creates
friction for every downstream consumer that wants visibility, and the
runtime cost without a subscriber is provably zero (a single relaxed
atomic load in the dispatcher). This matches the convention used by
`tokio`, `hyper`, `quinn`, and `rustls`.
