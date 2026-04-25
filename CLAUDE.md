# CLAUDE.md

Guidance for Claude Code working on this repository. Conventions
and invariants only — for API tutorials, follow the pointers to
source doc-strings, `docs/recipes/`, and `crates/nlink/examples/`.

## Project Overview

`nlink` is a Rust library for Linux network configuration via
netlink. The library is the deliverable; the `bins/{ip,tc,ss,nft,
wifi,devlink}` binaries exist as proof-of-concept demonstrations.

Key design invariants:
- **Custom netlink** — no `rtnetlink` / `netlink-packet-*`
  dependency. We own the wire format end-to-end.
- **Async/tokio native** via `AsyncFd`.
- **Library-first**: binaries are thin wrappers over typed APIs.
- **Single publishable crate** (`nlink`) with feature flags. All
  binaries are `publish = false`.
- Rust edition 2024.

## Build & Test

```bash
cargo build                               # all crates + bins
cargo build -p nlink                      # library only
cargo test -p nlink --lib                 # library unit tests

# Lint and dep hygiene before any commit
cargo clippy --workspace --all-targets --all-features -- --deny warnings
cargo machete                             # no unused deps
```

## Integration tests

Live under `crates/nlink/tests/integration/` and require root +
network namespaces. Maintainer runs `cargo test` as a regular
user, so root-gated tests **bit-rot silently** — they live behind
the `lab` feature and a privileged-CI gate (Plan 140 / Plan 142
Phase 0). Until that lands, validate root flows manually with
`--apply` example runners (e.g., `examples/netfilter/conntrack.rs
--apply`) and document the invocation in the recipe / plan.

```bash
cargo test --test integration --features lab --no-run
sudo ./target/debug/deps/integration-* --test-threads=1
```

For new tests that need root, gate with `nlink::require_root!()`
(early-returns `Ok(())` when `euid != 0`). For tests that depend
on a specific kernel module, also gate with
`nlink::require_module!("nf_conntrack")` — `has_module()` checks
`/sys/module/<name>` so it works for both loadable and built-in
features. For new examples, prefer the `--apply` runner pattern
over assertions.

## Architecture

| Layer | Path | Role |
|---|---|---|
| Library | `crates/nlink/` | Single publishable crate with feature flags |
| Binaries | `bins/{ip,tc,ss,nft,wifi,devlink}` | CLI demos consuming the library |
| Recipes | `docs/recipes/` | End-to-end markdown walkthroughs |
| Examples | `crates/nlink/examples/` | Runnable demos per subsystem |
| Plans | `*.md` at repo root | In-flight plans + roadmap (`128b-roadmap-overview.md`) |

Inside `crates/nlink/src/`:
- `netlink/` — the core protocol stack (always built). Submodules
  per RTNetlink concept (`tc.rs`, `filter.rs`, `action.rs`,
  `link.rs`, `route.rs`, `rule.rs`, `nexthop.rs`, `mpls.rs`,
  `srv6.rs`, `bridge_vlan.rs`, `fdb.rs`, …) and per non-RTNetlink
  protocol (`netfilter.rs`, `xfrm.rs`, `connector.rs`,
  `uevent.rs`, `audit.rs`, `selinux.rs`, `fib_lookup.rs`,
  `nftables/`, `genl/`).
- `netlink/genl/{wireguard,macsec,mptcp,ethtool,nl80211,devlink}/`
  — Generic Netlink families.
- `netlink/config/` — declarative `NetworkConfig` (diff + apply +
  reconcile).
- `netlink/{ratelimit,impair,diagnostics}.rs` — high-level helpers.
- `lab/` — namespace + integration-test harness (feature `lab`).

Types are zero-copy via the `zerocopy` crate (`#[repr(C)]` +
`FromBytes` + `IntoBytes` + `Immutable` + `KnownLayout`). No
unsafe pointer casts in `types/`.

### Feature flags

| Feature | Purpose |
|---|---|
| `sockdiag` | Socket diagnostics (`NETLINK_SOCK_DIAG`) |
| `tuntap` | TUN/TAP device management |
| `tc` | TC qdisc string-arg builders + handle parsing |
| `output` | JSON/text output formatting helpers |
| `namespace_watcher` | Inotify-based netns watching |
| `lab` | `nlink::lab` namespace + integration-test harness |
| `full` | All of the above |

## Type-safe units (Rate / Bytes / Percent)

The TC API takes typed-unit newtypes at every boundary. This
permanently kills the unit-confusion bug class — there's no way
to silently mistake bits-per-second for bytes-per-second.

```rust
use nlink::{Rate, Bytes, Percent};

let r = Rate::mbit(100);              // Rate::{mbit,gbit,kbit,bytes_per_sec,bits_per_sec}
let r: Rate = "100mbit".parse()?;     // tc-style string round-trips with Display
assert_eq!(Rate::mbit(100).to_string(), "100mbit");

let b = Bytes::kib(32);               // binary KiB; also kb (decimal), mb, mib, gb, gib
let p = Percent::new(1.5);            // clamped 0..=100; from_fraction(0.015) too

// Saturating arithmetic
Rate::mbit(8) * Duration::from_secs(1) == Bytes::mb(1);
Bytes::mb(1) / Duration::from_secs(1) == Rate::mbit(8);
```

Internal storage is bytes/sec (matches kernel's `tc_ratespec.rate`).
Earlier nlink had a long-standing bug where
`HtbClassConfig::new("100mbit")` shaped at 800 Mbps because
bits-per-second got silently treated as bytes-per-second. With
`Rate`, that mistake is a compile error.

## Type-safe TC handles (TcHandle / FilterPriority)

TC connection methods take typed handles, never `&str` / `u32`.

```rust
use nlink::TcHandle;

let h = TcHandle::new(1, 0x10);             // 1:10
let h = TcHandle::ROOT;                     // root qdisc; also INGRESS, CLSACT
let h: TcHandle = "1:a".parse()?;           // tc(8) notation round-trip
TcHandle::ROOT.is_root();                   // inspection helpers

// Connection methods take TcHandle (not &str)
conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb).await?;
conn.add_class_config("eth0", TcHandle::major_only(1), TcHandle::new(1, 1), cfg).await?;

// TcMessage::handle() / TcMessage::parent() return TcHandle
for q in &qdiscs {
    if q.parent().is_root() { /* … */ }
}
```

`FilterPriority` is a `u16` with documented bands (operator 1..=49,
recipe 100..=199, app 200..=999, system 1000..). nlink helpers
like `PerPeerImpairer` and `PerHostLimiter` install in the recipe
band so they don't fight operator-installed rules.

## TC API conventions

Every TC entity (qdisc, class, filter, action) follows one
shape. New TC code MUST match it; reviews bounce on drift.

### Typed config + fluent builder

```rust
use nlink::netlink::tc::HtbQdiscConfig;

let cfg = HtbQdiscConfig::new()
    .default_class(0x10)
    .r2q(10)
    .build();
```

- `pub fn new() -> Self`; fluent setters consume `self` and
  return `Self`; `pub fn build(self) -> Self` is a terminal
  no-op for symmetry (the kernel is the validator).
- Implements the relevant `QdiscConfig` / `FilterConfig` /
  `ActionConfig` trait — that's what `Connection<Route>` generic
  methods take.
- Public enums (mode/key kinds) carry `#[non_exhaustive]`.
  Public structs don't — fluent setters are the
  forward-compatible addition point.

### `parse_params` contract

```rust
impl FooConfig {
    pub fn parse_params(params: &[&str]) -> Result<Self> { ... }
}
```

- **Strict**: unknown tokens, missing values, and unparseable
  inner values all return
  `Error::InvalidMessage(format!("kind: ..."))`. **Silent
  skipping is a bug** — the legacy `tc::options::*` parsers
  swallow unknown tokens; the typed parsers exist to fix that.
- **Error shape**: every message starts with the kind name
  (`"htb: invalid r2q `foo` (expected unsigned integer)"`).
- **Token ordering**: any-order keyword. Positional optional
  args (`delay <time> [<jitter> [<corr>]]`) consume greedily
  up to the next keyword via a per-config `is_keyword` helper.
- **Aliases**: handle `tc(8)` synonyms (`classid`/`flowid`,
  `burst`/`buffer`/`maxburst`) in the same arm.
- **"Not modelled yet"**: when the kernel accepts a token the
  typed config doesn't carry, return a clear "not modelled by
  FooConfig" error pointing at the typed builder method.
  **Never silently fall back.**
- **Errors are stringly typed by design** — no typed parse-error
  variant. Format-string messages have proven readable across
  the 25 shipped parsers.

The sealed `nlink::ParseParams` trait formalizes the inherent
method for generic dispatch (`fn run<C: ParseParams>(p: &[&str])
-> Result<C>`). One impl per shipped typed config, each forwarding
to its inherent `parse_params`; the inherent method stays so
existing direct callers don't break. The bin's `dispatch!` macros
bind through the trait so the contract is type-checked, not just
convention.

### Deprecated modules

`nlink::tc::builders::{class,qdisc,filter,action}` and
`nlink::tc::options/<kind>.rs` are the original string-args
builders. **Deprecated since 0.14.0; deleted in 0.15.0 under
Plan 142 Phase 4.** Don't reach for them in new code. Don't add
new stringly-typed `add_class(kind, &[&str])`-shaped methods to
mirror the one remaining fossil — extend typed configs with
`parse_params` instead.

## Connections & namespaces

Canonical construction is the typed marker form:

```rust
use nlink::{Connection, Route, Generic, Wireguard};

let conn = Connection::<Route>::new()?;
let genl = Connection::<Generic>::new()?;
let wg   = Connection::<Wireguard>::new_async().await?;  // GENL: family resolution
```

For namespace-aware code, prefer `*_by_index` Connection methods
over `*_by_name` — the name variants read `/sys/class/net/` from
the host namespace, which is wrong inside a foreign netns. Build
the ifindex once via `conn.get_link_by_name("eth0").await?` and
pass it to subsequent calls.

```rust
use nlink::netlink::namespace;

// Plain (rtnetlink) — sync constructor
let conn: Connection<Route> = namespace::connection_for("myns")?;
// GENL families need async resolution
let wg: Connection<Wireguard> = namespace::connection_for_async("myns").await?;
```

The `nlink::lab` module (feature `lab`) provides `LabNamespace`
and `with_namespace` for integration tests + local CLI demos.
Drop deletes the namespace; failures `tracing::warn!`.

## Errors

All public methods return `nlink::Result<T>`. The error type is
`nlink::Error`; recovery is via `is_X()` predicates rather than
matching variants directly — see `crates/nlink/src/netlink/error.rs`.

```rust
match conn.del_qdisc("eth0", TcHandle::ROOT).await {
    Ok(()) => {}
    Err(e) if e.is_not_found() => {}        // also: is_already_exists,
    Err(e) if e.is_busy() => {}             //  is_permission_denied,
    Err(e) if e.is_invalid_argument() => {} //  is_no_device,
    Err(e) if e.is_timeout() => {}          //  is_not_supported,
    Err(e) => return Err(e),                //  is_network_unreachable
}
```

Specific not-found cases get typed variants
(`Error::QdiscNotFound { .. }`, etc.) for reconcile patterns.
Kernel errors carry `KernelWithContext` (operation name + args +
errno), so messages read like `"add_link(veth0, kind=veth): File
exists (errno 17)"`. Operation timeouts are opt-in via
`Connection::timeout(Duration)`; default is none.

## Observability

Every Connection method, every netlink request/ack/dump cycle
(TRACE), every connection lifecycle event (INFO), every GENL
family resolution (INFO), every multicast event (TRACE), and
every recipe-helper apply (INFO) emits a `tracing` span. Spans
cost nothing without a subscriber.

```bash
RUST_LOG="nlink::netlink::impair=info,nlink::netlink::connection=warn"
RUST_LOG="nlink[method=add_qdisc]=debug"      # one method by name
RUST_LOG=nlink=trace                          # everything
```

Full conventions in `docs/observability.md`.

## Cookbook

When the user asks "how do I X" and X is one of these, link the
recipe rather than re-synthesizing:

- [`per-peer-impairment`](docs/recipes/per-peer-impairment.md) —
  per-destination netem on shared L2 (HTB + flower + netem).
- [`bridge-vlan`](docs/recipes/bridge-vlan.md) — VLAN-aware bridge,
  trunk/access ports, VXLAN VLAN-to-VNI.
- [`bidirectional-rate-limit`](docs/recipes/bidirectional-rate-limit.md)
  — HTB egress + IFB ingress via `RateLimiter`.
- [`wireguard-mesh`](docs/recipes/wireguard-mesh.md) — 3-node mesh
  in `nlink::lab` namespaces.
- [`multi-namespace-events`](docs/recipes/multi-namespace-events.md)
  — `StreamMap` fan-in across N namespaces.
- [`conntrack-programmatic`](docs/recipes/conntrack-programmatic.md)
  — ctnetlink mutation + multicast NEW/DESTROY events.
- [`nftables-stateful-fw`](docs/recipes/nftables-stateful-fw.md) —
  table/chain/rule plumbing + atomic transactions.

Per-subsystem runnable examples live under
`crates/nlink/examples/`: `genl/{wireguard,macsec,mptcp,ethtool_*,
nl80211,devlink}.rs`, `netfilter/{conntrack,conntrack_events}.rs`,
`{audit,bridge,config,connector,diagnostics,events,fib_lookup,
impair,lab,namespace,nftables,ratelimit,route,selinux,sockdiag,
uevent,xfrm}/`. Read these directly when learning a subsystem;
they are kept current.

## Active work

The 0.15.0 release is organized under
[Plan 142](142-zero-legacy-typed-api-plan.md) (master plan,
"zero-legacy milestone"). Phases:

- **0** — CI harness (Plan 140) + sealed `ParseParams` trait
- **1** — filter side completion (Plan 138 + Plan 133 PR C +
  Plan 137 integration tests un-parked)
- **2** — XFRM write path (Plan 141)
- **3** — typed standalone-action CRUD (Plan 139 PRs A+B)
- **4** — **legacy deletion milestone** (Plan 139 PR C):
  `tc::builders::*` + `tc::options::*` deleted; zero
  `#[allow(deprecated)]` in `bins/tc`

Read Plan 142 first when picking up 0.15.0 work; phase detail
plans live alongside it. Roadmap entry point:
[`128b-roadmap-overview.md`](128b-roadmap-overview.md).

## Publishing

`nlink` is the only publishable crate (binaries have
`publish = false`).

```bash
cargo publish -p nlink
```
