---
to: nlink maintainers
from: nlink maintainers
subject: Netfilter capabilities expansion (ctnetlink mutation, events, expect, nfqueue, nflog)
target version: post-0.14.0 (0.15.0 or later; staged work)
date: 2026-04-21
status: PR A in progress — slice 1 (ConntrackBuilder + add/update/del/flush + 9 wire-format unit tests) and slice 2 (docs/recipes/conntrack-programmatic.md) landed 2026-04-22 under `[Unreleased]`. Remaining for PR A: integration tests under `lab`, examples/netfilter/conntrack.rs promotion. PRs B/C/D/E unstarted.
related: Plan 136 §2.2 row for `netfilter/conntrack.rs` (deferred pending the library extensions this plan describes)
---

# Netfilter Capabilities Expansion

## 0. Summary

Today `Connection::<Netfilter>` (`crates/nlink/src/netlink/netfilter.rs`)
is dump-only: `get_conntrack` and `get_conntrack_v6`, nothing else.
That was enough to build `ss`-style observability tools but falls
short of three user-facing use cases:

1. **Conntrack mutation.** Inject / update / delete / flush entries —
   required for NAT tooling, load-balancer control planes, and
   integration tests that need to pre-seed flow state. It's also the
   missing library surface that forced Plan 136 to defer the
   `netfilter/conntrack.rs` example promotion.
2. **Conntrack event subscription.** Multicast groups under
   `NFNLGRP_CONNTRACK_*` let an observer watch NEW/UPDATE/DESTROY
   events in real time. Used by flow collectors, security tooling,
   and live dashboards.
3. **Auxiliary ctnetlink objects.** `ct_expect` (expected-connection
   entries for ALG/helpers like FTP), conntrack zones, labels, and
   runtime-adjustable timeouts.

Optionally, the same NETLINK_NETFILTER socket also carries the
`nfqueue` and `nflog` subsystems, which let userspace accept/drop/mark
packets and receive kernel drop logs respectively. These are distinct
subsystems with their own designs; included here as phase-4/5 follow-ons.

This plan stages the work as **five independent PRs**, ordered by
user-value density. Each can ship on its own minor release.

## 1. Goals & non-goals

### Goals

1. **Ship ctnetlink mutation** (add / update / delete / flush).
2. **Ship ctnetlink event subscription** via the `EventSource` trait
   pattern already used by the Route/Nl80211/Ethtool connections.
3. **Ship `ct_expect`** query + mutation.
4. **Ship a `conntrack.rs` example** promoting the Plan 136 punt.
5. **Ship a recipe** (`docs/recipes/conntrack-programmatic.md`)
   showing a typical injection-plus-monitor workflow.
6. Optional: **`nfqueue`** (packet verdict pipeline) as a separate
   feature-gated subsystem. Large enough it should be its own PR.
7. Optional: **`nflog`** subsystem for userspace drop logging.

### Non-goals

1. **nftables.** Already implemented in `nlink::nftables` — this plan
   doesn't touch it.
2. **ipset.** Lives under NETLINK_NETFILTER but is a distinct
   subsystem with its own ID list; park for a later plan unless a
   concrete user asks.
3. **Kernel module loading / autoload.** Users run `modprobe
   nf_conntrack` / `nfnetlink_queue` / `nfnetlink_log` themselves;
   we surface clear errors when a module is missing.
4. **Packet manipulation in-kernel.** That's iptables/nftables
   territory. `nfqueue` is verdict-only from the library's side.
5. **Backward compat shims for iptables.** Use nftables instead.

---

## 2. Phase 1 — ctnetlink mutation (CRUD)

### 2.1. API sketch

```rust
// crates/nlink/src/netlink/netfilter.rs  (or a submodule once it grows)

/// Builder for a conntrack entry going in via RTM_NEW / RTM_DEL.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless submitted to the connection"]
pub struct ConntrackBuilder {
    zone: Option<u16>,
    mark: Option<u32>,
    labels: Option<Vec<u8>>,
    timeout: Option<Duration>,
    orig: ConntrackTuple,
    reply: Option<ConntrackTuple>,   // derive from orig for symmetric flows
    status: u32,                     // IPS_* flags (CONFIRMED, SEEN_REPLY, …)
    protoinfo: Option<ProtoInfo>,    // e.g. TCP state
    helper: Option<String>,
    id: Option<u32>,                 // for delete-by-id
}

impl ConntrackBuilder {
    pub fn new() -> Self;
    pub fn orig(self, tuple: ConntrackTuple) -> Self;
    pub fn reply(self, tuple: ConntrackTuple) -> Self;
    pub fn zone(self, zone: u16) -> Self;
    pub fn mark(self, mark: u32) -> Self;
    pub fn labels(self, labels: impl Into<Vec<u8>>) -> Self;
    pub fn timeout(self, d: Duration) -> Self;
    pub fn tcp_state(self, s: TcpConntrackState) -> Self;
    pub fn status(self, s: ConntrackStatus) -> Self;
    pub fn helper(self, name: impl Into<String>) -> Self;
    pub fn id(self, id: u32) -> Self;
    pub fn build(self) -> Self;
}

impl Connection<Netfilter> {
    // Already present:
    pub async fn get_conntrack(&self) -> Result<Vec<ConntrackEntry>>;
    pub async fn get_conntrack_v6(&self) -> Result<Vec<ConntrackEntry>>;

    // New:
    pub async fn add_conntrack(&self, entry: ConntrackBuilder) -> Result<()>;
    pub async fn update_conntrack(&self, entry: ConntrackBuilder) -> Result<()>;
    pub async fn del_conntrack(&self, entry: ConntrackBuilder) -> Result<()>;
    pub async fn del_conntrack_by_id(&self, id: u32) -> Result<()>;

    /// Flush all conntrack entries (optionally filtered by family / zone / mark).
    pub async fn flush_conntrack(&self) -> Result<()>;
    pub async fn flush_conntrack_by_zone(&self, zone: u16) -> Result<()>;
    pub async fn flush_conntrack_by_mark(&self, mark: u32, mask: u32) -> Result<()>;

    /// Query a single entry by exact tuple match.
    pub async fn get_conntrack_entry(&self, tuple: &ConntrackTuple)
        -> Result<Option<ConntrackEntry>>;
}
```

### 2.2. Wire format

CTA attributes, IPCTNL_MSG_CT_NEW / CT_DELETE / CT_GET. All fields
already appear in the reader — we're reusing parsing, only flipping
the emit direction. Reference: kernel
`include/uapi/linux/netfilter/nfnetlink_conntrack.h`.

Key unknowns that need a small research pass before implementation:

- Exact semantics of `NLM_F_CREATE | NLM_F_EXCL` vs
  `NLM_F_CREATE | NLM_F_REPLACE` on CT_NEW (replace-or-error vs
  upsert).
- Whether `reply` tuple must be supplied for NAT-less injections, or
  the kernel mirrors `orig` when absent.
- Order of CTA_STATUS bits required for a committed entry
  (`IPS_CONFIRMED | IPS_SEEN_REPLY | IPS_ASSURED`?) vs just
  `IPS_CONFIRMED`.

### 2.3. Tests (integration)

Gated behind `#[cfg(feature = "lab")]` so they can use the Plan 135
lab helpers.

- `test_conntrack_inject_and_query`: inject a synthetic TCP entry
  in a namespace, dump, assert it appears.
- `test_conntrack_delete_by_tuple`: add → delete → assert gone.
- `test_conntrack_flush_zone`: add entries in zones 0 and 1, flush
  zone 1, assert only zone 0 remains.
- `test_conntrack_mark_update`: add → update mark → dump → assert.

All run in a throwaway `LabNamespace` so the host table is untouched.
Kernel modules required: `nf_conntrack`, `nf_conntrack_netlink`,
`nf_conntrack_ipv4` (or v6). Skip-if-not-root + skip-if-modules-missing
at the top of each test.

### 2.4. Effort

~3-4 days (builder + emit path + error mapping + tests + one
example promotion).

---

## 3. Phase 2 — ctnetlink event subscription

### 3.1. API sketch

Mirror the existing `EventSource` pattern. Multicast groups live at
`NFNLGRP_CONNTRACK_NEW` / `_UPDATE` / `_DESTROY`.

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConntrackEvent {
    New(ConntrackEntry),
    Update(ConntrackEntry),
    Destroy(ConntrackEntry),
}

impl Connection<Netfilter> {
    /// Subscribe to conntrack multicast groups. Default: NEW + DESTROY.
    pub fn subscribe(&mut self, groups: &[ConntrackGroup]) -> Result<()>;
    pub fn subscribe_all(&mut self) -> Result<()>;
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ConntrackGroup {
    New,
    Update,
    Destroy,
    ExpNew,
    ExpDestroy,
}

// EventSource impl: events() / into_events() returning Stream<Item = Result<ConntrackEvent>>.
```

### 3.2. Wire format

Reuses the same CT_NEW / CT_DELETE / CT_GET message layout the dump
path already parses — the *multicast* socket just delivers one
message per event instead of a dump batch. Minimal new code; mostly
mirror `Connection<Route>::events`.

### 3.3. Tests (integration)

- `test_conntrack_events_new_destroy`: in a namespace, subscribe →
  open a veth pair + generate ICMP → assert NEW followed by
  DESTROY for the matching tuple.
- `test_conntrack_events_stream_survives_drain`: spam enough events
  that the kernel multicast buffer overflows; assert we surface a
  clear error (don't silently drop).

### 3.4. Effort

~2 days (smaller than Phase 1 because parsing already exists).

---

## 4. Phase 3 — `ct_expect` and conntrack helpers

### 4.1. Why

Expectations encode "when I see *this* related packet, associate it
with *that* master flow." Used by FTP (data channel), SIP, H.323,
and other ALG-bearing protocols. Also load-balancers that pre-seed
return-path mappings.

Without `ct_expect` we can't demo any real ALG flow and can't build
integration tests for NAT helpers.

### 4.2. API sketch

```rust
pub struct ConntrackExpect {
    pub tuple: ConntrackTuple,    // the expected tuple
    pub mask: ConntrackTupleMask, // wildcard bits
    pub master: ConntrackTuple,   // master connection that "owns" this
    pub timeout: Duration,
    pub helper: Option<String>,   // e.g. "ftp"
    pub zone: Option<u16>,
    pub flags: u32,
}

impl Connection<Netfilter> {
    pub async fn get_expectations(&self) -> Result<Vec<ConntrackExpect>>;
    pub async fn add_expectation(&self, e: ConntrackExpectBuilder) -> Result<()>;
    pub async fn del_expectation(&self, e: &ConntrackExpect) -> Result<()>;
    pub async fn flush_expectations(&self) -> Result<()>;
}
```

Subsystem IDs: `NFNL_SUBSYS_CTNETLINK_EXP` (2). Attributes under
`enum ctattr_expect` in the same kernel header.

### 4.3. Tests

- `test_expect_add_and_delete`: add an expectation, dump, delete.
- `test_expect_timeout_enforced`: add with 1s timeout, sleep 2s,
  dump, assert gone.

### 4.4. Effort

~2 days.

---

## 5. Phase 4 — nfqueue (packet verdict pipeline)

### 5.1. Why

`nfnetlink_queue` lets userspace receive packets that matched a
`queue` verdict in nftables / iptables, inspect them, and return an
accept / drop / repeat / mark verdict. Common uses:

- Transparent proxies that need to rewrite application-layer data
  without rebuilding the kernel stack.
- Stateful DPI for compliance / inspection.
- Research tooling for packet mangling.

### 5.2. Separate subsystem, separate feature

`nfqueue` is distinct enough (its own bind / config-per-queue /
packet-receive / verdict cycle) that it should live in a submodule
behind a `nfqueue` feature flag:

```
crates/nlink/src/netlink/netfilter/
  mod.rs           # existing ctnetlink + umbrella Connection<Netfilter>
  conntrack.rs     # split out of the current monolith
  expect.rs        # Phase 3
  nfqueue.rs       # Phase 4 (feature-gated)
  nflog.rs         # Phase 5 (feature-gated)
```

### 5.3. API sketch

```rust
pub struct NfQueueConfig {
    pub queue_num: u16,
    pub mode: NfQueueMode,      // None / Meta / Packet
    pub max_len: Option<u32>,   // copy range
    pub fail_open: bool,
    pub conntrack: bool,        // include CT info in metadata
}

pub struct NfQueuePacket {
    pub id: u32,                // verdict ID (echo in NfQueueVerdict)
    pub queue_num: u16,
    pub hw_protocol: u16,
    pub hook: u8,
    pub mark: u32,
    pub ifindex_in: Option<u32>,
    pub ifindex_out: Option<u32>,
    pub timestamp: Option<SystemTime>,
    pub payload: Vec<u8>,
}

pub enum NfQueueVerdict {
    Accept,
    Drop,
    Queue { new_queue_num: u16 },
    Repeat,
    Stop,
}

impl Connection<NfQueue> {
    pub async fn bind(&self, queue_num: u16, cfg: NfQueueConfig) -> Result<()>;
    pub async fn unbind(&self, queue_num: u16) -> Result<()>;
    pub async fn set_verdict(&self, id: u32, queue_num: u16, verdict: NfQueueVerdict,
                             payload_patch: Option<&[u8]>) -> Result<()>;
    pub fn packets(&self) -> impl Stream<Item = Result<NfQueuePacket>> + '_;
}
```

### 5.4. Effort

~5-7 days. Bigger because the whole packet-rx / verdict-tx loop is
new code, not a refactor of the dump-path parser.

### 5.5. Compete with userspace libs?

Rust ecosystem has `nfqueue` + `nfnetlink` crates. Decide whether to
build our own or interop with those. Lean: build our own, gated
behind the `nfqueue` feature, so consumers get a single nlink
dependency. But only if Phase 1-3 haven't already burned the
time budget; otherwise document the existing crate as the
recommended option.

---

## 6. Phase 5 — nflog (userspace drop logs)

### 6.1. Why

`nfnetlink_log` is the modern replacement for `ipt_ULOG`. A
nftables/iptables rule with `log group <N>` sends matching packets
to userspace listeners bound to that group. Used by SIEM agents,
drop-reason dashboards, security audit trails.

### 6.2. API sketch

Symmetric to `nfqueue` but one-way (no verdicts):

```rust
pub struct NfLogConfig {
    pub group: u16,
    pub copy_mode: NfLogCopyMode,  // None / Meta / Packet
    pub copy_range: Option<u32>,
    pub timeout: Option<Duration>,
    pub flags: u16,
}

pub struct NfLogPacket { /* similar to NfQueuePacket but immutable */ }

impl Connection<NfLog> {
    pub async fn bind(&self, group: u16, cfg: NfLogConfig) -> Result<()>;
    pub async fn unbind(&self, group: u16) -> Result<()>;
    pub fn packets(&self) -> impl Stream<Item = Result<NfLogPacket>> + '_;
}
```

### 6.3. Effort

~3 days.

---

## 7. Files touched (estimate across all phases)

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/netfilter.rs` → `.../netfilter/mod.rs` | Split monolith | wash |
| `crates/nlink/src/netlink/netfilter/conntrack.rs` | New CRUD API + event source | ~700 |
| `crates/nlink/src/netlink/netfilter/expect.rs` | Expectation CRUD | ~350 |
| `crates/nlink/src/netlink/netfilter/nfqueue.rs` | Feature-gated verdict pipeline | ~800 |
| `crates/nlink/src/netlink/netfilter/nflog.rs` | Feature-gated log subscription | ~400 |
| `crates/nlink/Cargo.toml` | `nfqueue` + `nflog` features | ~5 |
| `crates/nlink/tests/integration/netfilter/*.rs` | Per-phase integration tests | ~400 |
| `crates/nlink/examples/netfilter/conntrack.rs` | Plan 136 §2.2 promotion | ~200 |
| `crates/nlink/examples/netfilter/conntrack_events.rs` | Phase 2 demo | ~100 |
| `crates/nlink/examples/netfilter/nfqueue_inspect.rs` | Phase 4 demo (feature-gated) | ~150 |
| `docs/recipes/conntrack-programmatic.md` | New recipe | ~250 |
| `CHANGELOG.md` | Entries per phase | per phase |

Total across all phases: ~3400 LOC code + tests + docs.

---

## 8. Phasing (which PRs, in what order)

| PR | Scope | Size | Unlocks |
|---|---|---|---|
| A | Phase 1: ctnetlink CRUD | ~1000 LOC | Plan 136 conntrack example, NAT tooling, LB control planes |
| B | Phase 2: event subscription | ~400 LOC | Flow-collector use cases, live dashboards |
| C | Phase 3: ct_expect / helpers | ~500 LOC | ALG testing, stateful proxy work |
| D | Phase 4: nfqueue | ~1000 LOC | Transparent proxies, DPI research, feature-gated |
| E | Phase 5: nflog | ~550 LOC | SIEM / audit integration, feature-gated |

**Recommended order: A → B → C. Phase 4/5 only if demand materialises.**

`docs/recipes/conntrack-programmatic.md` lands with PR A. Phase 3's
ALG recipe (if we write one) lands with PR C.

---

## 9. Test strategy

All phases require root + network namespaces + kernel modules. Gate
integration tests behind `#[cfg(feature = "lab")]` so they can use
`LabNamespace` for isolation; skip-if-not-root at the top.

Generating traffic for conntrack tests is straightforward with a
veth pair + forwarding enabled, but fragile in CI. Options:

1. **In-kernel traffic via `ping` / `nc` spawned into a `LabNamespace`.**
   Works; slow-ish but reliable.
2. **Synthetic injection via `add_conntrack` followed by observation.**
   Doesn't validate the kernel state machine, only the wire format.
3. **Both — use (1) for end-to-end, (2) for fast CI checks.**

Lean (3). Tag the slow end-to-end tests with `#[ignore]` + a
`--ignored` CI stage so a `cargo test --features lab` run stays
under a minute.

---

## 10. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| CTA_STATUS bit semantics differ across kernels | Medium | Test against Linux 5.15, 6.1, 6.6, 6.11 in CI; only emit the minimum bits needed |
| nfqueue verdict-ID reuse on a slow consumer drops packets | High | Document backpressure contract: if the stream falls behind `copy_range * queue_depth` bytes, kernel drops; don't pretend we can prevent it |
| `ct_expect` semantics depend on loaded helper modules (`nf_conntrack_ftp` etc.) | Medium | Error clearly when helper isn't loaded; don't try to autoload |
| Scope creep from ipset / bpfilter | Low | Explicit non-goals in §1 |
| Competing userspace libs already exist | Medium | For nfqueue/nflog, document the alternatives in the module docs so users can choose |
| Kernel multicast buffer overrun drops events | High (for Phase 2) | Surface `Error::Overrun` cleanly; document in the recipe; add `--buffer-size N` to the example |

---

## 11. What we are NOT doing

- **nftables integration** — it's already a first-class module;
  nothing in this plan changes it.
- **ipset** — separate subsystem, park for a later plan.
- **bpfilter** — upstream dormant; skip.
- **Per-queue throughput benchmarks.** Library API, not a perf
  engineering task.
- **Automatic module loading.** Users `modprobe`; we surface clean
  errors.
- **Conntrack stats (`nf_conntrack_count`).** Cheap to add but not
  part of this plan's user stories; tack on to Phase 1 if
  convenient.

---

## 12. Definition of done (per phase)

### PR A — ctnetlink CRUD
- [ ] `ConntrackBuilder` with all documented setters
- [ ] `add_conntrack` / `update_conntrack` / `del_conntrack` /
      `del_conntrack_by_id` / `flush_conntrack*` / `get_conntrack_entry`
- [ ] Integration tests exercise add → query → update → delete
- [ ] `examples/netfilter/conntrack.rs` promoted to write-path demo
- [ ] `docs/recipes/conntrack-programmatic.md`
- [ ] CHANGELOG entry

### PR B — event subscription
- [ ] `ConntrackEvent` enum + `EventSource` impl on
      `Connection<Netfilter>`
- [ ] `subscribe` / `subscribe_all` methods
- [ ] `ConntrackGroup` enum re-exported at crate root
- [ ] `examples/netfilter/conntrack_events.rs`
- [ ] Integration test covering NEW + DESTROY round-trip
- [ ] CHANGELOG entry

### PR C — expectations
- [ ] `ConntrackExpect` + `ConntrackExpectBuilder`
- [ ] `get_expectations` / `add_expectation` / `del_expectation` /
      `flush_expectations`
- [ ] Integration test with a helper-backed flow
- [ ] CHANGELOG entry

### PR D — nfqueue (feature-gated)
- [ ] `nfqueue` feature in `Cargo.toml`
- [ ] `Connection<NfQueue>` protocol state + bind/unbind/verdict API
- [ ] Stream-based packet reception
- [ ] One end-to-end example behind the feature flag
- [ ] CHANGELOG entry

### PR E — nflog (feature-gated)
- [ ] `nflog` feature in `Cargo.toml`
- [ ] `Connection<NfLog>` + subscription API
- [ ] One example behind the feature flag
- [ ] CHANGELOG entry

---

## 13. Open questions

1. **Connection typing.** Should `nfqueue` / `nflog` be new
   protocol-state types (`Connection<NfQueue>`, `Connection<NfLog>`)
   that all live under `NETLINK_NETFILTER`, or should they be
   orthogonal handles on the same `Connection<Netfilter>`? Lean: new
   types, because the bind-per-queue state doesn't fit the existing
   conntrack model cleanly.
2. **`ConntrackStatus` as a bitflags type.** We use raw `u32` today;
   a `bitflags`-backed type would be more discoverable. Worth adding
   to `nlink::netlink` as a dependency, or hand-roll a small enum?
3. **Conntrack zone API ergonomics.** Exposing zones as `Option<u16>`
   everywhere vs a scoped connection that implicitly filters all
   operations to one zone (`conn.in_zone(5).get_conntrack()`). Lean
   `Option<u16>` first, reassess if users ask.
4. **Recipe scope.** Does "conntrack programmatic" cover both mutation
   and events, or split into two recipes? Lean one recipe with both —
   it's how users actually use the two APIs together.

---

## 14. Interaction with existing plans

- **Plan 136 §2.2 (`netfilter/conntrack.rs`)** — unblocked by PR A.
  Land the example promotion in the same PR as PR A (§4.1 and §4.2
  of the Plan 136 recipe template).
- **Plan 135 PR B** — we still want a `docs/recipes/conntrack-*.md`
  entry in the recipe index; add it as PR A's DoD item rather than
  retroactively updating Plan 135.
- **Plan 133 PR C (`BasicFilter` ematch)** — orthogonal; both touch
  netfilter-adjacent areas but don't share code.

---

End of plan.
