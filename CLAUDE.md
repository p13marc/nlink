# CLAUDE.md

Guidance for Claude Code working on this repository. Conventions
and invariants only — for API tutorials, follow the pointers to
source doc-strings, `docs/recipes/`, and `crates/nlink/examples/`.

## Project Overview

`nlink` is a Rust library for Linux network configuration via
netlink. The library is the deliverable; the `bins/{ip,tc,ss,nft,
wifi,devlink}` binaries exist as proof-of-concept demonstrations.
Every produced binary is `nlink-` prefixed (`nlink-ip`, `nlink-tc`,
…) so it never shadows the real system tool — the `[[bin]] name` in
each `bins/*/Cargo.toml` matches the package name. CLI integration
tests reference binaries via `env!("CARGO_BIN_EXE_nlink-<tool>")`.

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
user, so root-gated tests would **bit-rot silently** if they
weren't both (a) gated with `nlink::require_root!()` (so they
skip cleanly as non-root) and (b) run under the privileged-CI
gate that landed in 0.15.0 (Plan 140 — see
`.github/workflows/integration-tests.yml`; runs on every push/PR
to master under a container with `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`
+ `seccomp=unconfined`). For local validation as a non-root user,
the `--apply` example runners stay the canonical channel (e.g.,
`examples/netfilter/conntrack.rs --apply`).

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
| Plans | GitHub issues + `CHANGELOG.md ## [Unreleased]` | In-flight work + roadmap (a per-cycle `plans/` dir is recreated when a cycle opens and deleted at cut) |

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
  reconcile + opt-in purge).
- `netlink/{resync,resync_ext,reflector}.rs` — ENOBUFS-resync event
  streams, the `ResyncStreamExt` combinators, and the kube-rs-style
  `Store<K,V>` watch-cache (`ReflectExt::reflect`).
- `netlink/{ratelimit,impair,diagnostics}.rs` — high-level helpers.
  Both `RateLimiter` and `PerHostLimiter` expose the idempotent
  `reconcile{,_dry_run,_with_options}` trio alongside the
  destructive `apply` (0.24, #169).
- `sockdiag/` — high-level socket-diagnostics API (feature
  `sockdiag`; the wire layer is `netlink/sockdiag.rs`): typed
  queries + `FilterExpr` (ss grammar) with a full
  `INET_DIAG_REQ_BYTECODE` compiler (`bytecode.rs` —
  `compile_filter` lowers ports/addresses/or/not kernel-side and
  hoists `state` into `idiag_states`; client-side backstop applies
  automatically when inexact), socket→process/cgroup attribution
  (`procmap.rs` — `/proc` reads are fine here, the sysfs audit gate
  only covers `netlink/`), cookie-keyed TCP goodput deltas
  (`rate.rs` — TCP-only; UDP diag has no byte counters), and typed
  CC internals (`CcInfo`: BBR/DCTCP/vegas). All 0.24, #162/#163/#171.
- `lab/` — namespace + integration-test harness (feature `lab`).

Types are zero-copy via the `zerocopy` crate (`#[repr(C)]` +
`FromBytes` + `IntoBytes` + `Immutable` + `KnownLayout`). No
unsafe pointer casts in `types/`.

### Feature flags

| Feature | Purpose |
|---|---|
| `sockdiag` | Socket diagnostics (`NETLINK_SOCK_DIAG`) |
| `tuntap` | TUN/TAP device management |
| `output` | JSON/text output formatting helpers |
| `namespace_watcher` | Inotify-based netns watching |
| `lab` | `nlink::lab` namespace + integration-test harness |
| `syscall_batch` | `recvmmsg`/`sendmmsg` batching wired into eager + streaming dump paths (0.16+; opt-in for one soak release) |
| `serde` | `Serialize` + validating `Deserialize` on the declarative config types (`NetworkConfig` round-trips through JSON/YAML; addresses/routes as CIDR strings, MACs as `aa:bb:..`, validated via `try_from`). Also gates `ConfigDiff`/`NftablesDiff`/result-type `Serialize`. Pulls `serde_json` for the `NetworkConfig::{from_json_str,to_json_string}` helpers. |
| `schemars` | JSON Schema (draft 7) for `NetworkConfig` via `json_schema()` / `json_schema_value()` — wire into editor `json.schemas`/`yaml.schemas` or CI validation. Opt-in; implies `serde`; faithful to the human-facing JSON shape (CIDR strings, not parsed structs). 0.23+. |
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
conn.add_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 1), cfg).await?;

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
  skipping is a bug** — the typed parsers exist precisely
  because the old string-args builders swallowed unknown tokens.
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
  the 69 shipped parsers (35 qdisc + 4 class + 11 filter + 19 action).

The sealed `nlink::ParseParams` trait formalizes the inherent
method for generic dispatch (`fn run<C: ParseParams>(p: &[&str])
-> Result<C>`). One impl per shipped typed config, each forwarding
to its inherent `parse_params`; the inherent method stays so
existing direct callers don't break. The bin's `dispatch!` macros
bind through the trait so the contract is type-checked, not just
convention.

### No legacy string-args builders

The old `tc::builders::{class,qdisc,filter,action}` modules and
the per-kind `tc::options/<kind>` parsers were deleted in 0.15.0.
Don't add new stringly-typed `add_class(kind, &[&str])`-shaped
methods to bring them back — extend typed configs with
`parse_params` instead. See
[`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md)
for the per-symbol migration table.

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

### Namespace-safe APIs

nlink provides `*_by_index` variants alongside `*_by_name` for
every resource lookup. The `_by_index` variants take a kernel
ifindex directly, so they're safe to call from any process mount
namespace — the index is always relative to the connection's
netns. The `_by_name` variants read `/sys/class/net/` from the
calling process's mount namespace, which is convenient for simple
cases but surprises inside foreign netns. **For namespace-aware
code (CNI plugins, multi-tenant managers, integration-test
harnesses that touch foreign netns), prefer the `_by_index`
variants — or pre-resolve names once via
`conn.get_link_by_name(...)` and pass the index to subsequent
calls.**

This is a deliberate design choice that distinguishes nlink from
`neli` and `vishvananda/netlink`, both of which leave namespace
handling to the caller — a documented footgun in
[Cilium issue #40280](https://github.com/cilium/cilium/issues/40280).
nlink's typed `InterfaceRef::Index(u32)` plus the per-method
`_by_index` variants make namespace-correct code natural to write.

If you want compile-time enforcement instead of "prefer", use
the `Index(_)` variant of `InterfaceRef` (or pass a `u32`
ifindex directly to methods that accept it) — the `_by_name`
methods become a deliberate convenience choice rather than a
default.

#### `util::ifname` sysfs reads — namespace policy

`util::ifname::{name_to_index, index_to_name, list_interfaces}`
read from `/sys/class/net/` in the **calling process's mount
namespace**. They are only used by the `bins/` CLI tools and
never by internal library paths. The audit script
`scripts/audit-sysfs-in-lib.sh` (wired into CI as a separate
gate) fails the build if a `/sys/class/net/` or `/proc/sys/`
read appears in `crates/nlink/src/netlink/` outside the
documented exceptions — currently only `sysctl.rs`, where
`/proc/sys/...` is the kernel-blessed way to read sysctls
from a process attached to a netns.

For library code touching foreign netns, the policy is:

1. Use `Connection::get_link_by_name` (netlink-based; ifindex
   resolved through `RTM_GETLINK` in the connection's netns).
2. Or use the `_by_index` API variants and pre-resolve the
   ifindex via the connection.
3. If a new file genuinely needs sysfs (e.g. ethtool fallback,
   diagnostics), add it to `ALLOWED` in
   `scripts/audit-sysfs-in-lib.sh` and document the rationale
   in a rustdoc comment.

### Connection diagnostics + sockopts

Two `Connection<P>` methods control kernel-side diagnostic
surfaces; both are silently no-ops on kernels that don't recognize
the underlying sockopt:

- `conn.enable_strict_checking(true)?` —
  `NETLINK_GET_STRICT_CHK` (kernel 5.0+). Validates dump filters
  against the running kernel's attribute set; surfaces
  client/kernel-version mismatches as errors instead of silent
  misbehavior. Off by default; opt in when developing against a
  specific kernel.
- `conn.set_ext_ack(true)?` — `NETLINK_EXT_ACK` (kernel 4.12+).
  **On by default** — disabling is rarely useful. When on (and
  the kernel cooperates), error responses carry human-readable
  TLVs that nlink parses and stitches into `Error::Kernel::Display`
  output. Example: `errno = 22 (EINVAL)` becomes
  `"attribute IFLA_MTU rejected: value 0 out of range (at request
  offset 24)"`. See `Error::Kernel::ext_ack`.

### Concurrency (0.19 F1 fix + opt-in dispatcher mode, #134)

`Connection<P>` is `Send + Sync` and safe to share across tokio
tasks via `Arc<Connection<P>>`. Every request/response method
acquires an internal `tokio::sync::Mutex` so concurrent callers
serialize cleanly instead of racing on `recv_msg`. Trade-off:
shared-`Arc<Connection>` requests run in sequence rather than
in parallel. For true parallel throughput use
`ConnectionPool<P>` — each task gets its own connection (and
its own kernel-side socket queue, which the kernel processes
in parallel).

**Stream-shape APIs hold the lock for their lifetime — in the
default mutex mode.** `conn.events().await`,
`conn.into_events().await`, `conn.dump_stream::<T>(...).await?`
and the `*_with_resync` constructors are **async** (0.19 Finding
B). On a plain connection a long-lived events subscriber blocks
concurrent requests until dropped — use a second Connection,
`ConnectionPool`, or **`with_dispatcher()`** (below), which lifts
this restriction entirely.

**Opt-in dispatcher mode (`with_dispatcher()`) — #134.** The
per-Connection `Dispatcher` ships a per-`nlmsg_seq` background
recv-driver. Opt a connection in with
`Connection::<P>::new()?.with_dispatcher()` and a single driver
task owns recv and demultiplexes every frame: unicast responses
to per-seq channels, multicast (`seq == 0`) frames to event
subscribers. The payoff — **events and requests on the same
connection no longer serialize**, the exact F1 regression #134
was filed for. `events()`/`into_events()`, `dump_stream`, the
GENL `dump_typed_stream`, and the mixed subsystems
(xfrm/netfilter/ethtool/`command`/`batch`) all work in this mode;
single-message unicast requests **pipeline** instead of waiting on
the mutex.

Two constraints survive because the kernel imposes them, not the
library: **dumps still serialize** per socket (`netlink_dump_start`
→ `EBUSY` on a 2nd in-flight dump — the dump-serialization lock is
held for a dump's lifetime even in dispatcher mode), and for
genuinely parallel dumps you still want `ConnectionPool<P>` (one fd
per task, kernel-parallel).

**The default stays the mutex — deliberately.** A plain
`Connection<P>` serializes request/response through an internal
`tokio::sync::Mutex` (the 0.19 F1 fix). This keeps the simple
one-shot path lean (no background task, no runtime-context
requirement). `with_dispatcher()` is the **concurrency opt-in**;
reach for it when one connection must serve a long-lived event
stream *and* concurrent requests. The mutex also remains the
correct per-socket serialization for the single-reader subsystems
(sockdiag/audit/nftables/nl80211/devlink/…), whose only operations
are dumps that must serialize anyway.

```rust
// Default: shared Connection across tasks — serialized but correct,
// and lean (no background driver).
let conn = Arc::new(Connection::<Route>::new()?);
for _ in 0..16 {
    let c = conn.clone();
    tokio::spawn(async move { c.get_links().await });
}

// Opt-in dispatcher: events + requests on ONE connection coexist.
let conn = Arc::new(Connection::<Route>::new()?.with_dispatcher());
conn.subscribe_all()?;
let mut events = conn.events().await;          // long-lived subscriber…
let links = conn.get_links().await?;           // …doesn't block this request

// Parallel dump fanout: still the pool — each task gets its own fd.
let pool = Arc::new(ConnectionPool::<Route>::new(8)?);
for _ in 0..16 {
    let p = pool.clone();
    tokio::spawn(async move { p.acquire().await?.get_links().await });
}
```

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
exists (errno 17)"`. **Operation timeout defaults to 30 seconds**
(Plan 171 — closes the "hidden hang" class). Override with
`Connection::timeout(Duration)`; opt out (rarely useful) with
`.no_timeout()`. The default surfaces any kernel response
anomaly as `Error::Timeout` instead of an indefinite block.

## Recv-loop shape (canonical)

Every netlink response-reading loop in the lib follows the same
shape. Two structural requirements every new loop MUST meet —
both surfaced by the 0.16 cycle's CI hang (`send_batch` lacked
the seq filter; took 22 min of GHA wall-clock + 3 push-iterations
to localize):

1. **Filter by `nlmsg_seq`** before any other check. The kernel
   may deliver stale responses from earlier requests on the same
   fd, or multicast notifications interleaved with unicast
   replies. `if header.nlmsg_seq != seq { continue; }` is
   mandatory.
2. **Terminate on the right marker.** Dumps terminate on
   `NLMSG_DONE`. Batch commits (`NFNL_MSG_BATCH_*`) terminate
   on the **BATCH_END's ACK specifically** — not the first
   per-op ACK, which can fire mid-batch and leave the loop
   thinking the batch is done.

Canonical template:

```rust
let seq = self.socket().next_seq();
// ... build + send request, tracking start/end seqs for batches ...

loop {
    let data = self.recv_with_timeout().await?;   // Plan 171: 30s default
    let mut done = false;
    for msg in MessageIter::new(&data) {
        let (header, payload) = msg?;
        if header.nlmsg_seq != seq {              // (1) seq filter
            continue;
        }
        if header.is_error() {
            let err = NlMsgError::from_bytes(payload)?;
            if err.is_ack() {
                // For batch commits: return only on the
                // BATCH_END seq's ACK; per-op ACKs continue.
                done = true;
                break;
            }
            return Err(err.into_error(payload));
        }
        if header.is_done() {                     // (2) end marker
            done = true;
            break;
        }
        // ... accumulate payload ...
    }
    if done { break; }
}
```

Plan 172 enforces this template across all 9 recv-loops in the
lib. The audit table is in Plan 172 §2.1.

## Parser robustness

Defensive parsing policy for any code that walks attribute
chains or fixed-size structs out of kernel response bytes.
Plan 193 (0.19) pinned the conventions; the audit scripts
under `scripts/audit-recv-loop-error-handling.sh` enforce
them.

Three rules. Future parsers MUST follow all three.

1. **Accept-larger-than-expected on fixed-size structs.**
   Use `if buf.len() < EXPECTED_SIZE { error }`, NOT
   `if buf.len() != EXPECTED_SIZE { error }`. The kernel
   grows struct-typed attributes over time
   (`IFLA_INET6_CONF` is the canonical example —
   netlink-packet-route #232 tracked the bug class). Read
   the prefix, ignore trailing bytes.

2. **Pathological-length input guards on header-driven
   loops.** Any chain walker that reads a length-field from
   each entry header must:
   - Validate `entry_len >= MIN_HEADER_SIZE` on entry; skip
     remainder if not (prevents slice-index panic).
   - Treat `entry_len == 0` as end-of-chain or skip-and-log;
     never let `offset` fail to advance (prevents infinite
     loop). The bug class tracks
     netlink-packet-route #152.

3. **Recoverable per-message parse failures.** Event
   parsers (`impl EventSource for *`, `parse_*_event`
   dispatchers) that walk `MessageIter::new(data)` MUST
   silently skip parse errors rather than propagating via
   `?`. Use:

   ```rust
   for (header, payload) in MessageIter::new(data).flatten() { ... }
   // OR
   for msg_result in MessageIter::new(data) {
       let Ok((header, payload)) = msg_result else { continue };
       ...
   }
   ```

   One malformed frame from a future kernel MUST NOT kill a
   long-lived multicast subscriber. Tracks neli #305.

The `scripts/audit-recv-loop-error-handling.sh` CI gate
greps for `?` operator inside `MessageIter` walking loops in
event-parser contexts and fails on hits. New parsers
inherit the policy.

## UAPI constants

Because nlink owns its wire format end to end, every attribute id,
message type and enum value in the crate was hand-transcribed from
a kernel header. That is a transcription task, and transcription
drifts — silently, because the kernel accepts a well-formed
message that names the wrong attribute. The 0.25.0 cycle found
**eight** such drifts; the worst (#196) meant `ethtool` link speed
read as `None` on every interface, forever, with no error anywhere.

`scripts/audit-uapi-constants.sh` (CI gate, #232) diffs every
`#[repr(uN)]` enum in `crates/nlink/src/` against
`/usr/include/linux` on every push — 644 discriminants across 62
enums today. **Every such enum must be classified:**

- mapped to its kernel prefix in `scripts/audit-uapi-constants.map`
  (with `Variant -> KERNEL_SUFFIX` overrides where the names don't
  line up, or `Variant -> !skip` for an nlink sentinel), or
- declared nlink-only in `scripts/audit-uapi-constants.allowlist`,
  **with a reason**.

An unclassified enum fails the build: an unclassified enum is an
unchecked one. Be suspicious of allowlist entries — "there's no
header constant for it" is exactly what a drifted enum would say.
`scripts/test-audit-uapi-constants.sh` is the self-test companion;
it reconstructs the real drifts and asserts the gate catches them.

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
- [`per-process-bandwidth`](docs/recipes/per-process-bandwidth.md) —
  unprivileged per-socket/process/cgroup TCP goodput from sock_diag
  polling: kernel-side `FilterExpr` pre-filtering +
  `SocketRateTracker` + `SocketOwnerMap`/`CgroupPathMap` (0.24+;
  TCP-only — UDP diag has no byte counters).
- [`conntrack-programmatic`](docs/recipes/conntrack-programmatic.md)
  — ctnetlink mutation + multicast NEW/DESTROY events.
- [`nftables-stateful-fw`](docs/recipes/nftables-stateful-fw.md) —
  table/chain/rule plumbing + atomic transactions.
- [`nftables-declarative-config`](docs/recipes/nftables-declarative-config.md) —
  declare a whole ruleset, `cfg.diff(&conn)` + `diff.apply(&conn)`
  (atomic single-batch commit) + `apply_reconcile` for concurrent
  mutators. Mirror of `NetworkConfig` for nftables. The `nft` bin
  demos it as `nft reconcile <file>` / `nft diff <file>` (desired-state
  DSL → diff → apply; #109). For the interface-side `NetworkConfig`,
  the `serde` feature gives a validating JSON/YAML round-trip
  (`NetworkConfig::from_json_str`; #108) — see
  [`docs/library.md`](docs/library.md#declarative-network-configuration).
- [`define-your-own-genl-family`](docs/recipes/define-your-own-genl-family.md)
  — declare a complete custom GENL family in ~30 lines via
  `nlink-macros` (`#[genl_family]` + `#[derive(GenlMessage)]` +
  `conn.send_typed(req).await?`).
- [`dpll-monitor`](docs/recipes/dpll-monitor.md) — enumerate
  clock-synchronization hardware (SyncE / PTP / GNSS) via
  `Connection<Dpll>`, push-based event stream
  (`subscribe_monitor()` + `DpllEvent` via `EventSource`), detect
  holdover acquisition, diagnose lock loss via
  `DpllLockStatusError`. Telco-RAN / time-sync / SmartNIC
  control-plane use case (0.16+).
- [`tx-hw-shaping`](docs/recipes/tx-hw-shaping.md) — TX hardware
  shaping (per-NIC, per-queue, or scheduler-node bandwidth/burst/
  priority/weight) via `Connection<NetShaper>` (kernel 6.13+).
  Capability handshake via `get_caps` before `set_shaper` so
  drivers with partial support don't surprise you. Telco /
  SmartNIC / SR-IOV multi-tenancy use case (0.16+).
- [`openvpn-dco`](docs/recipes/openvpn-dco.md) — OpenVPN 2.7
  data-channel offload via `Connection<Ovpn>` + the declarative
  `OvpnConfig` mirror of `WireguardConfig`. Peers + AEAD keys
  installed in-kernel; atomic `key_swap` rekey cutover;
  multicast `peer-del-ntf` / `key-swap-ntf` / `peer-float-ntf`.
  Kernel 6.16+ (0.21+, Plan 197).
- [`events-with-resync`](docs/recipes/events-with-resync.md) —
  ENOBUFS-resilient event loop (`ResyncedEvent`, resync markers,
  `into_events_with_resync`) + the `ResyncStreamExt`/`ReflectExt`
  combinators and the `Store` watch-cache.
- [`nftables-watch-with-resync`](docs/recipes/nftables-watch-with-resync.md)
  — subscribe to nftables multicast events and recover from ENOBUFS
  via resync redump.
- [`xfrm-ipsec-tunnel`](docs/recipes/xfrm-ipsec-tunnel.md) — IPsec SA/SP
  setup + the `Connection<Xfrm>: EventSource` monitor stream.
- [`connection-pool`](docs/recipes/connection-pool.md) — `ConnectionPool<P>`
  for kernel-parallel dump fan-out (one fd per task).
- [`cgroup-classification`](docs/recipes/cgroup-classification.md) —
  cgroup-based TC classification.
- [`error-handling-patterns`](docs/recipes/error-handling-patterns.md) —
  `is_X()` recovery predicates + typed not-found variants.

Per-subsystem runnable examples live under
`crates/nlink/examples/`: `genl/{wireguard,macsec,mptcp,ethtool_*,
nl80211,devlink,dpll,net_shaper,ovpn}.rs`, `macros/define_taskstats.rs`,
`netfilter/{conntrack,conntrack_events}.rs`, `pool/parallel_dump.rs`,
`{audit,bridge,config,connector,diagnostics,events,fib_lookup,
impair,lab,namespace,nftables,ratelimit,reflector,route,selinux,
sockdiag,uevent,xfrm}/`. Read these directly when learning a subsystem;
every shipped example is registered + builds clean under
`cargo build --workspace --all-targets` (the
`audit-example-registration` CI gate enforces zero orphans).

**Convention — every example .rs MUST be registered in
`crates/nlink/Cargo.toml`.** Cargo only auto-discovers examples
at the top level of `examples/`; any file in a subdirectory
(`examples/route/foo.rs`, `examples/genl/bar.rs`, …) is invisible
to `cargo build --workspace --all-targets` unless declared as an
`[[example]] name=… path=…` block. Skipping the registration means
the example bit-rots silently against API changes.
`scripts/audit-example-registration.sh` enforces the convention;
run it locally before merging a new example.

## Active work

**0.24.0 shipped 2026-07-03** (`v0.24.0` tagged; both crates on
crates.io). Headline narrative in `CHANGELOG.md ## [0.24.0]` +
`docs/migration_guide/0.23.0-to-0.24.0.md`. A sockdiag/events/
nftables depth release from the 2026 roadmap pass (#170): the #160
XFRM dump-body fix; #165 Rule/Nexthop/NsId/Mdb `NetworkEvent`
variants + `#[non_exhaustive]` on
`ConfigDiff`/`StackDiff`/`WireguardConfigDiff` + `subscribe_all()`
joining every typed-event group; #162 socket→process/cgroup
attribution; #164 typed nftables rule-expression decoding
(`RuleExpr`); #169 ergonomics batch (`del_*_if_exists`, WG device
bootstrap `ensure_devices`, `NamespaceSpec` facade `_in` variants,
`RateLimiter::reconcile`); #171 `SocketRateTracker` + the
`parse_tcp_info` tail-field fix; #163 full INET_DIAG_BC bytecode
compiler + `CcInfo` structs + the `InetExtension::mask()` off-by-one
fix.

The **next cycle is open on `master`** — new work lands in
`CHANGELOG.md ## [Unreleased]` and is promoted to the next
`## [X.Y.0]` at cut time. (CI runs on every push/PR to master, so
the old "work on a release branch, don't push to master" note no
longer applies.) The workspace version stays at the released 0.24.0
until the cycle's first breaking PR bumps it to 0.25.0 (the
cargo-semver-checks convention; precedent 041a289).

Cycle-sized roadmap items still open from #170: #166 (modern-kernel
telemetry families), #167 (spec-first netlink codegen), #168
(record/replay mock transport).

The 0.23.0 cycle resolved the **#134–#137 follow-on epic**: the
opt-in dispatcher mode is feature-complete (#134 —
`Connection::with_dispatcher`, events + streams + mixed subsystems
coexist on one connection), GENL command unification (#135),
`Connection::<Ovpn>::attach_socket` + `NetlinkSocket::send_with_fds`
(#136), and the entire **#137 audit/coverage backlog**: full nl80211
read audit (PHY/wiphy, scan/BSS, station-info, channel survey) with
two id-drift wire-bug fixes, XFRM monitor `EventSource`, bridge
`BRIDGE_VLANDB_ENTRY`/`GOPTS`, net_shaper group shaping, MPLS/SRv6/
NextHop struct audit, declarative nftables sets (`DeclaredSet`),
`schemars` JSON Schema, `NetworkConfig` declarative purge (Plan 205),
the `Store` reflector watch-cache (Plan 195), the newtype `From`/`Into`
sweep (Plan 201), `TableName` newtype, `LinkStats` accessor convention,
pedit `munge` DSL, `WireguardConfig::{from_wg_quick,client}`, and
property-based parser-robustness harnesses. **Only intentionally
deferred:** `backon`-based `StreamBackoff` (Plan 195 — reconnect
backoff composes at the spawn-loop level) and `ip vrf exec` (needs
cgroup2 + eBPF `sock_bind`, untestable under the non-root CI gate).

Open follow-on work is tracked as GitHub issues, not in `plans/`.

Per-release upgrade guides:
[`docs/migration_guide/`](docs/migration_guide/README.md) — write
a new one when cutting any minor release; the README explains the
convention.

## Publishing

Two publishable crates as of 0.16: `nlink` and `nlink-macros` (the
proc-macro derives `nlink::macros::*` re-exports). Both bins set
`publish = false`.

**Publish nlink-macros FIRST** when cutting — `nlink`'s `Cargo.toml`
pins `nlink-macros` with `version = "..."` alongside the path dep
so `cargo publish -p nlink` resolves the dep on crates.io;
publishing nlink before nlink-macros fails with "no matching
version found."

Use `scripts/cut-release.sh X.Y.Z` (Plan 175) to walk the full
cut: pre-flight, CHANGELOG promotion, CI green-gate, dry-runs,
merge, tag, publish (macros → index-poll → nlink), GitHub release
(length-aware body), next-cycle branch. The script confirms at
every irreversible step. Manual equivalent for emergencies:

```bash
cargo publish -p nlink-macros
# wait ~30s for crates.io to index
cargo publish -p nlink
```

**Dry-run gotcha**: `cargo publish -p nlink --dry-run` will FAIL
unless the matching `nlink-macros` version is already on
crates.io. The dry-run checks against the live registry; the
publish order is "macros first, then nlink." Skip the
`nlink --dry-run`; rely on the macros dry-run + the real publish
sequence. `cut-release.sh` skips it automatically with a comment.

**Plan-file cleanup**: a `plans/` directory is per-cycle working
memory. When a cycle cuts + publishes, delete the whole thing in a
follow-up commit; the durable narrative lives in
`CHANGELOG.md ## [X.Y.Z]` + `docs/migration_guide/<from>-to-<to>.md`,
and any not-yet-implemented work becomes a GitHub issue before the
files go. (The 0.20/0.21 plan cycle was cleaned up this way — its
deferred items are tracked in #134–#137; earlier, the 0.16 → 0.17
transition deleted 23 0.16 plans + slimmed Plan 169 to its open
Phase 3.) When the next cycle opens, recreate `plans/` with a fresh
`INDEX.md`.
