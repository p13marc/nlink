---
title: nlink — code-level analysis (bugs, improvements, features)
audience: maintainer
status: draft for review
date: 2026-05-23
methodology: three parallel agents (codebase bug hunt, web research on netlink CVEs and competitor state, public API review) + my own spot-verification on the highest-severity claims
distinct-from: `STRATEGIC_ANALYSIS.md` (high-level positioning, 1.0 strategy). This file is code-level and actionable.
---

# nlink — code-level analysis

This report is a complement to `STRATEGIC_ANALYSIS.md`, not a replacement.
That document covered positioning and the 1.0 path. This one covers
**actual bugs in the current source**, **concrete improvements with
file/line references**, and **specific features** the ecosystem evidence
says are worth adding.

Structure:

1. [Bugs to fix](#1-bugs-to-fix) — verified issues, prioritized by severity
2. [Code-quality improvements](#2-code-quality-improvements) — not bugs but worth doing
3. [Higher-level API gaps](#3-higher-level-api-gaps) — what users have to write today that they shouldn't
4. [Kernel features to add](#4-kernel-features-to-add) — ranked by ecosystem evidence, not by my prior speculation
5. [Quick wins for 0.16](#5-quick-wins-for-016) — sub-day items
6. [Sources & methodology notes](#6-sources--methodology-notes)

---

## 1. Bugs to fix

Listed in severity order. Findings marked **(verified)** I read the code
myself. Findings marked **(reported)** come from an exploration agent and
match the file I'd expect; spot-check before fixing.

### 1.1 CRITICAL — namespace restoration failure swallowed `socket.rs:138` (verified)

`NetlinkSocket::new_in_namespace` does `setns(target)` → create socket →
`setns(original)`. If the **restoration** `setns` fails (`socket.rs:134-142`),
the code currently does:

```rust
if restore_ret < 0 {
    eprintln!(
        "warning: failed to restore original namespace: {}",
        std::io::Error::last_os_error()
    );
}
result  // still returns the socket
```

**What's wrong**: the socket is fine — it lives in the target namespace,
that's the intended behavior. But the **calling thread** is now stuck in
the target namespace. Any subsequent `setns`-using operation on that
thread (including the next `new_in_namespace` call, or any
`/proc/thread-self/ns/*` read) will operate in the wrong netns. And the
caller has no way to know: the only signal is `eprintln!` to stderr,
which library code shouldn't be writing to at all.

**Who breaks**: anyone using nlink to manage multiple namespaces from a
multi-threaded process (Kubernetes pod managers, service meshes, CNI
plugins). Tokio's multi-threaded runtime will park a different task on
that thread later, and that task will silently run in the wrong netns.

**Fix**: return `Err` instead of `eprintln!`. The restore failure is rare
enough that propagating it is safer than masking it. Suggested error:
`Error::NamespaceRestoreFailed { source: io::Error, thread_state: "still in target netns" }` so the caller can log the specific failure.

**Effort**: ~30 min including a test that simulates the failure (mock
out `libc::setns` or use a permission-restricted ns FD).

**Breaking?**: signature stays `Result<Self>`; behavior changes from
"sometimes silently returns a socket while leaving the thread in the
wrong netns" to "always either restores cleanly or fails loud". This is
arguably a bug fix, not a breaking change, but worth a CHANGELOG callout.

---

### 1.2 HIGH — `config::diff` doesn't detect qdisc parameter changes `config/diff.rs:434` (verified earlier in CI cycle)

The qdisc diff compares only the **kind** (`htb` vs `netem` etc.), not
the parameters. So changing an HTB's `rate` from 100mbit to 1gbit in a
`NetworkConfig` and re-applying produces no operation — the diff sees
"both sides are HTB" and emits nothing. The TODO is at line 434, marker
`// TODO: Could check detailed parameters here`.

**Who breaks**: anyone using `NetworkConfig::apply()` for declarative
qdisc management — the configuration silently doesn't take effect on
parameter-only changes.

**Fix**: extend the comparison to call `config.write_options()` on both
sides into temporary buffers and byte-compare. Or, for the common
parameter-by-parameter approach, expose each typed config's fields and
diff them. Byte-compare is simpler and works for any `QdiscConfig`.

**Effort**: ~2 hours including a regression test in
`tests/integration/config.rs` for parameter-only change.

---

### 1.3 MEDIUM — `bitset.rs` clones each name in `sort_by_key` `bitset.rs:283` (verified)

In commit `e47e5ca` I changed `sort_by(|(_, a), (_, b)| a.cmp(b))` to
`sort_by_key(|(_, name)| (*name).clone())` to satisfy clippy's
`unnecessary_sort_by` lint. That's wrong — clippy's auto-suggestion
allocated when it didn't need to. The right fix:

```rust
// Either restore the original (and allow the lint locally):
#[allow(clippy::unnecessary_sort_by)]
entries.sort_by(|(_, a), (_, b)| a.cmp(b));

// Or use sort_unstable_by_key with a reference key (no clone):
entries.sort_unstable_by_key(|(_, name)| name.as_str());
```

The second form is idiomatic and lint-clean. **Use that.**

**Who breaks**: any user calling `set_features` or
`set_link_modes` — each call clones every feature name. On hardware
with hundreds of features, that's a real allocation cliff.

**Effort**: 5 min + verify lib tests still pass.

---

### 1.4 MEDIUM — `route.rs` `write_delete_with_interfaces` omits `RTA_METRICS` `route.rs:824-882` (reported, plausible)

`write_add` writes `RTA_METRICS` when set; `write_delete_with_interfaces`
doesn't. The kernel's behavior here is undocumented and probably benign
(routing tables don't normally key on metrics for delete), but the
asymmetry is suspicious. Worth either (a) confirming the kernel ignores
metrics on delete and adding a code comment explaining the omission, or
(b) writing metrics to be safe.

I'd commit to (a) — read the kernel source for `fib_table_delete` and
document the behavior. Cheaper than the alternative of always writing.

**Effort**: 30 min reading + 10 min commenting.

---

### 1.5 LOW — `setns` SAFETY comment missing on `geteuid` call `lab/mod.rs:297` (reported, cosmetic)

`unsafe { libc::geteuid() == 0 }` has no SAFETY comment. `geteuid` is
infallible and safe to call from anywhere, but the convention across the
rest of the codebase is to document every unsafe block. Add one line.

**Effort**: 1 min.

---

### 1.6 LOW — `parse.rs` `.chars().nth(1).unwrap()` `util/parse.rs:65` (reported, cosmetic)

Length-checked before the `nth`, so the unwrap is safe. But idiomatic
Rust would use `s.as_bytes().get(1)` to avoid both the allocation in
`chars()` and the unwrap. Tiny cleanup.

**Effort**: 2 min.

---

### 1.7 Bug class to watch — attribute-bounds validation

Research found multiple recent kernel CVEs in the same class (CVE-2024-53141
`bitmap_ip_uadt` OOB write, CVE-2026-31407 conntrack netlink message
validation). nlink is on the *userspace* side of the wire so we're
parsing kernel-trusted data, but a buggy kernel module on a malicious
host could still produce malformed attributes.

**Action**: audit every `from_bytes` / parser in the codebase for length
assumptions that could underflow. The rust-netlink ecosystem had a
near-miss with `RouteNextHopBuffer` underflow that wasn't assigned a CVE
because Rust caught it at panic-time rather than letting it become a
memory-corruption. Worth fuzz-targeting parsers as a 0.16+ item (per
strategic analysis §2.7).

---

## 2. Code-quality improvements

Not bugs, but worth doing.

### 2.1 Use structured logging, not `eprintln!`

`grep -rn "eprintln!" crates/nlink/src/` — every hit is a smell. Library
code shouldn't write to stderr; use `tracing::warn!` or `tracing::error!`
with structured fields. Daemons routing stderr to journald lose context
otherwise.

**Files**: `socket.rs:138`, `lab/mod.rs` (a couple of teardown warnings),
plus any in the integration test helpers. ~6 sites total.

**Effort**: 30 min.

---

### 2.2 Audit `unwrap()` / `expect()` outside `#[cfg(test)]`

Previous reviews found ~40 unwraps but only in test code. Re-run with
fresh eyes — any new ones in production code? Specifically search
`crates/nlink/src/netlink/genl/` and `crates/nlink/src/netlink/nftables/`
which have churned recently.

**Effort**: 30 min audit, fixes are per-site.

---

### 2.3 Re-export hygiene at crate root

`lib.rs` re-exports `BridgeVlanBuilder`, `FdbEntry`, `Diagnostics`,
`Generic`, `Wireguard`, `Route`, `TcHandle`, `ParseParams`,
`ReconcileReport`. But NOT:

- `Ipv4Route`, `Ipv6Route`, `RouteMetrics`, `NextHop`
- `RuleBuilder`
- `LinkConfig`, `AddressConfig`, `RouteConfig`, `NeighborConfig`,
  `ActionConfig` (the extension traits)
- `Ipv4Address`, `Ipv6Address`

The asymmetry pushes users into long imports
(`nlink::netlink::route::Ipv4Route` etc.) and makes the trait surface
hard to discover. Add ~10 lines of `pub use` to `lib.rs`.

**Effort**: 15 min including verifying `cargo doc` cross-references still
resolve.

**Breaking?**: no, purely additive.

---

### 2.4 Document the namespace-safety convention on `_by_index` methods

The lib has many `*_by_index` variants alongside `*_by_name`. The
`_by_index` form is namespace-safe (the index is relative to the
namespace the connection is in); the `_by_name` form reads
`/sys/class/net/` from the **process**'s mount namespace, which is
typically the host. CLAUDE.md documents this once; the actual doc
comments on `*_by_index` methods don't repeat it.

For a CNI plugin or similar multi-namespace user, this is a footgun.
Add a "# Namespace safety" doc block to every `*_by_index` method
(template-copyable; ~20 sites). Document the inverse on `*_by_name`
methods ("operates on the current process's `/sys/class/net/`; use
`*_by_index` inside foreign netns").

**Effort**: 1 hour mostly mechanical.

---

### 2.5 Make `Connection::<Wireguard>::new()` a compile error, not a runtime trap

GENL families (Wireguard, Macsec, Mptcp, Ethtool, Nl80211, Devlink) need
async family-ID resolution. `Connection::<Wireguard>::new()` currently
compiles but returns a connection with family ID 0; the first operation
fails with a confusing error. Use a sealed marker trait
`SyncConstructible` or similar that only the non-GENL protocols
implement, and bound `Connection::<P>::new()` on it.

**Effort**: 2 hours.

**Breaking?**: yes, but it turns silent breakage at runtime into a
compile error — the right kind of break. Reserve for 0.16 (already a
semver-minor cycle).

---

### 2.6 Sealed `Connection::<P>::new_async()` story

Mirror image: `new_async()` should only exist on protocols that need
async family resolution. Currently I think it's available for all,
which makes the "do I need .await?" question ambiguous.

**Effort**: 2 hours (paired with §2.5).

---

## 3. Higher-level API gaps

These are concrete user patterns that take more code than they should.

### 3.1 `wait_link_up(iface, timeout)` helper

The "create a veth, bring it up, wait for it to actually be up before
adding addresses" sequence is everywhere in integration tests and
container-init code. Currently users hand-wire `subscribe()` + event
loop + filter + timeout. ~15 lines that should be one method.

**Proposed**:

```rust
impl Connection<Route> {
    /// Wait for an interface to reach the IFF_UP state.
    ///
    /// Polls or subscribes (impl-detail) until the kernel reports the
    /// interface as up, or `timeout` elapses. Returns `Error::Timeout`
    /// on deadline.
    pub async fn wait_link_up(
        &self,
        iface: impl Into<InterfaceRef>,
        timeout: Duration,
    ) -> Result<()>;
}
```

Implementation: subscribe to LINK group, poll once to handle "already
up", then wait for the next state change.

**Effort**: 3 hours including tests for: (a) already up, (b) transitions
during wait, (c) timeout, (d) interface deleted during wait.

---

### 3.2 `get_link_stats(iface)` helper

`LinkMessage` already carries stats (`rx_bytes`, `tx_packets`, etc.) but
there's no one-line "get stats for this interface" call. Users do
`get_link_by_name(iface)?.unwrap().stats()` (3 ops, fallible Option to
deal with).

**Proposed**:

```rust
impl Connection<Route> {
    pub async fn get_link_stats(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<LinkStats>;
}
```

`LinkStats` is a small typed struct (already exists in `link.rs`).

**Effort**: 1 hour.

---

### 3.3 Streaming dump APIs for `routes`, `links`, `neighbors`, `fdb`

`get_routes()` etc. return `Vec<T>`. On a BGP router with 1M routes
this allocates gigabytes. The strategic analysis flagged this; it
remains the single biggest scalability cliff in the lib.

**Proposed**:

```rust
impl Connection<Route> {
    pub fn stream_routes(&self) -> impl Stream<Item = Result<RouteMessage>>;
    pub fn stream_links(&self) -> impl Stream<Item = Result<LinkMessage>>;
    pub fn stream_neighbors(&self) -> impl Stream<Item = Result<NeighborMessage>>;
}
```

Keep the existing `get_*` (eager `Vec`) for convenience.

**Effort**: 1-1.5 days (the lower-layer dump iteration already exists
internally; the change is at the boundary). Touches
`connection.rs::send_dump` and per-subsystem facades.

---

### 3.4 ENOBUFS resync helper on subscriber sockets

[Cilium issue #40280](https://github.com/cilium/cilium/issues/40280)
calls this out as a pan-ecosystem pain point. Multicast subscribers
that fall behind get `ENOBUFS` from the kernel; the conventional
recovery is to re-dump the current state and resume the stream.
Currently nlink leaves this to the user.

**Proposed**: `Connection::<P>::events_with_resync()` returns a stream
that handles `ENOBUFS` automatically — on overflow, runs a one-shot
dump to re-sync, then re-attaches the multicast stream. Users get
"events with implicit state replay" semantics.

**Effort**: 2 days. Non-trivial because the resync dump and the
multicast stream are different code paths; combining them cleanly takes
design work. Worth it — every serious downstream consumer reinvents
this.

---

### 3.5 Error recovery recipe

Per strategic analysis §2 / Cilium's documented pain points. Cover:

- EAGAIN / ENOBUFS — when to retry, when to back off, when to resync.
- Idempotency via `NLM_F_EXCL` (add succeeds vs returns `EEXIST`).
- SA / SP conflicts on XFRM (delete-then-add vs replace).
- Namespace cleanup on error paths.
- "I held a connection across a process fork" — the netns trap.

**Effort**: half a day of writing, no code.

---

### 3.6 `aya` co-demo example

Adjacent ecosystem research confirms `aya` is the BPF-in-Rust ecosystem
and it does TC program loading via `tcx` (Linux 6.6+) but has no
high-level netlink helpers. nlink could ship an example showing:

1. Load an XDP / TC eBPF program with `aya`.
2. Attach via `tcx` (kernel 6.6+) or fall back to nlink's TC `add_filter`
   (`bpf` action) on older kernels.
3. Monitor counters / stats via nlink.

This is an **integration showcase**, not new lib code. Useful for
marketing and as a copy-paste starting point for users.

**Effort**: 1 day.

---

## 4. Kernel features to add

The strategic analysis's feature table was largely correct, but research
sharpens priorities. Updates and corrections:

### 4.1 ~~`netkit` link kind~~ — **already supported** ✓

I was wrong in the strategic analysis. `NetkitLink` exists in
`link.rs:2018-2124` with full coverage: mode (L2/L3), policy,
peer_policy, scrub, peer_scrub, MTU. The only gap is an integration
test (the strategic analysis claimed netkit support was missing entirely
— that was outdated).

**Action**: add an integration test under `tests/integration/link.rs`
with `require_module!("netkit")`. ~30 min.

---

### 4.2 nftables `flowtable` — **really missing**, real strategic value

Verified: `grep -r flowtable crates/nlink/src/netlink/nftables/` returns
nothing. This is the headline nftables fastpath feature (kernel 5.x
cycle). Used by routers / firewalls doing high-throughput forwarding
with hardware offload (`NF_FLOWTABLE_HW_OFFLOAD` on capable NICs).

**Effort**: 2-3 days. New `FlowtableBuilder` + `add_flowtable` /
`del_flowtable` Connection methods + the corresponding nftables
expressions to add flows to the table. Plus a recipe.

---

### 4.3 XFRM IPsec offload (`XFRMA_OFFLOAD_DEV`)

Kernel 6.11 extended XFRM crypto offload to IPv6 ESP and IPv4 UDP-encap
ESP. Real demand from anyone running IPsec at scale (cloud, telco).
The SA builder already exists in `xfrm.rs`; this is adding an
`.offload(dev, flags)` setter.

**Effort**: 1 day.

---

### 4.4 Per-NAPI configuration via netlink (kernel 6.13)

`netdev-genl` exposes NAPI queues + configuration since 6.8, and 6.13
added per-NAPI config writes. nlink has a `Netdev` family? Let me note
the gap and verify before scoping.

**Action**: audit; if missing, add. Likely 1-2 days.

---

### 4.5 TX H/W shaping via `net_shaper` (kernel 6.13)

Generic netlink interface for TX hardware shaping with introspection +
devlink rate support. Brand new, demand is still nascent, but it's the
right time to ship support before downstream users build hacks.

**Effort**: 2 days.

---

### 4.6 nftables `NFT_TABLE_F_PERSIST` (kernel 6.9)

Persistent tables that survive ruleset flushes. Small addition to the
existing nftables `Table` builder — add `.persist(true)` setter.

**Effort**: 1 hour.

---

### 4.7 Devlink `rate` + port-function-state

Strategic analysis already flagged this. Cloud + SmartNIC users want
it; nlink has Devlink scaffolding but no rate-shaping helpers. Confirmed
absent.

**Effort**: 2 days.

---

### 4.8 NOT worth doing in 0.16

Deferring with rationale:

- **`tcx` BPF attach hooks** — `aya` now does TCX attachment in-tree
  (verified via `aya/programs/tc/` docs). nlink doing TCX without BPF
  program loading would be incomplete; the right path is the **co-demo
  example** (§3.6) showing aya + nlink interop, not a parallel TCX
  surface in nlink.
- **MPTCP userspace path-manager** — userspace PM is niche; in-kernel PM
  covers the common case. Open issues only.
- **nl80211 MLO** — Wi-Fi 7 specific; nlink's `wifi` bin is already
  marked as low-priority POC. Defer until someone files an issue.
- **CNI plugin demo bin** — research confirms there's no production
  Rust CNI plugin in 2026. Sart, masap/rust_cni, passcod/cni-plugins
  are all hobby projects. The market doesn't exist yet; building this
  is speculation, not value delivery.

---

## 5. Quick wins for 0.16

If you want a tight, high-leverage 0.16 cut, here's the must-do list
ordered by effort/value:

| # | Item | Effort | Section |
|---|---|---|---|
| 1 | Fix namespace-restore-swallow bug (`socket.rs:138`) | 30 min | §1.1 |
| 2 | Fix bitset clone-in-sort (`bitset.rs:283`) | 5 min | §1.3 |
| 3 | Fix config diff TODO (`diff.rs:434`) | 2 hours | §1.2 |
| 4 | Re-export hygiene in `lib.rs` | 15 min | §2.3 |
| 5 | Error-handling recipe (`docs/recipes/`) | half day | §3.5 |
| 6 | `wait_link_up()` helper | 3 hours | §3.1 |
| 7 | `get_link_stats()` helper | 1 hour | §3.2 |
| 8 | nftables `NFT_TABLE_F_PERSIST` | 1 hour | §4.6 |
| 9 | `netkit` integration test (close the gap) | 30 min | §4.1 |
| 10 | Streaming dump APIs (routes/links/neighbors) | 1.5 days | §3.3 |

**Total**: ~3 focused days for items 1-9, +1.5 days for streaming
APIs. That's a real 0.16.

Defer to 0.17 (each is multi-day with broader scope):

- nftables flowtable (§4.2)
- ENOBUFS resync helper (§3.4)
- XFRM offload (§4.3)
- Devlink rate (§4.7)
- `aya` co-demo (§3.6)

---

## 6. Sources & methodology notes

### Verified personally (read the code)

- §1.1 socket.rs namespace restore — confirmed at `socket.rs:114-145`
- §1.3 bitset.rs clone — confirmed at `bitset.rs:283`
- §4.1 netkit already supported — confirmed at `link.rs:2018-2124`
- §4.2 flowtable absent — confirmed via grep

### Trusted from agents (high-confidence, didn't re-verify)

- §1.2 config diff TODO — agent found at `diff.rs:434`, matches my prior
  grep for TODOs in the codebase (this one's been in the source since
  early plans)
- §1.4 route metrics asymmetry — agent finding; plausible but I'd
  confirm by reading kernel `fib_table_delete` before fixing
- §1.5/1.6 cosmetic items — low risk to take on trust

### Web-verified ecosystem evidence

- Cilium issue #40280 (Go netlink pain points)
- vishvananda/netlink 1.3.1 changelog (unknown-actionType crash; netkit
  attrs)
- rtnetlink crate stagnation (last release 0.21, April 2024)
- Linux kernel release notes 6.7 → 6.13 via kernelnewbies.org
- aya `programs/tc/` docs confirming TCX is in-tree, no external netlink dep
- Cilium 1.18 release notes confirming netkit still beta, no Rust components

### Caveats

- The agent's findings about `route.rs` metrics omission (§1.4) are
  plausible but I didn't read kernel source to confirm; treat the fix
  as research-and-confirm rather than apply-immediately.
- The agent reported the GitHub releases page for `netlink-packet-route`
  is stale relative to crates.io. If you want exact version dates for
  benchmarking, `cargo info netlink-packet-route` is authoritative.
- I made one cargo public-api error in earlier sessions claiming
  trait-method addition with default impl is non-breaking — it's
  semver-additive but cargo-public-api flags it. Worth documenting in
  the 0.16 release notes when shipping the streaming/wait_link_up
  methods (none of those are breaking, but the public-api diff WILL be
  non-empty).

---

## Bottom line

**The library is in good shape.** Three categories of work to consider:

1. **One critical bug** (`socket.rs:138`) that should be fixed regardless of
   any release cadence. 30 min.
2. **~3 days of quick wins** that, together, materially improve the
   library and constitute a strong 0.16 cut on their own.
3. **~1 week of medium-effort items** (flowtable, ENOBUFS resync,
   streaming API completion, aya co-demo) that could come either in
   0.16 if you want a longer cycle, or in 0.17.

The biggest single-feature win for users is the **streaming dump API**
(§3.3) — it's the only addition that changes what nlink can scale to.

The biggest single-feature win for adoption is the **`aya` co-demo**
(§3.6) — co-marketing with an established Rust eBPF crate that's
already doing TCX attachment in-tree but lacks high-level netlink
helpers. It's an integration play, not a new feature, and it's the
cheapest path to "nlink-shaped projects you can point at."

End of analysis.
