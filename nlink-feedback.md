# nlink feedback from the nlink-lab 158 arc

**Date:** 2026-05-30
**Audience:** nlink maintainer.
**Author:** nlink-lab maintainer (the canonical downstream consumer).
**nlink version reviewed:** `0.18.0`.
**Scope:** issues, ergonomic gaps, and feature requests collected
while implementing the seven-plan 158 arc against nlink 0.18 in
nlink-lab. Every item is grounded in a concrete downstream
workaround or test failure; nothing speculative.

---

## TL;DR — read this table first

| # | Item | Severity | Suggested fix size | Status |
|---|------|----------|--------------------|--------|
| 1 | `add_link(VlanLink)` parent name→ifindex resolution races with the immediately prior `add_link` | **HIGH (correctness)** | ~10–40 LOC | blocks declarative parent+child in one config |
| 2 | `NetworkConfig::apply` iterates `links_to_add` in declared order — no dependency-aware reordering | medium (correctness) | docstring + optional ~40 LOC topo-sort | works around with two-pass |
| 3 | `Error::from_errno_ext_ack` silently negates the input — counterintuitive | medium (footgun) | 1-line rustdoc OR 1-line normalization | hit it in a unit test |
| 4 | `Box<nlink::Error>` as `#[source]` breaks the `downcast_ref` chain walk | medium (footgun) | 1-paragraph rustdoc | backed out boxing in nlink-lab |
| 5 | `ConfigDiff` has no inherent `.apply(&conn, opts)` method | low (ergonomic) | ~15 LOC thin wrapper | use `cfg.apply()` (re-runs diff) |
| 6 | `apply::apply_diff` free fn isn't re-exported from `config` mod | low (ergonomic) | 1 line | as above |
| 7 | `ApplyOptions` has no builder methods | low (ergonomic) | ~15 LOC | use struct-literal syntax |
| 8 | `RouteBuilder::new` doesn't accept the `"default"` magic string | low (ergonomic) | ~5 LOC special-case | translate to `0.0.0.0/0` downstream |
| 9 | No `Serialize` derive on `ConfigDiff` / `NftablesDiff` | low (feature) | `serde` feature gate | use Display string fallback |
| 10 | `LinkBuilder::vxlan` missing `.local()` / `.port()` / `.underlay_dev()` | low (feature) | ~15 LOC | Vxlan stays imperative |
| 11 | `LinkBuilder::bond` missing `ad_select`/`lacp_rate`/`downdelay`/`updelay`/`resend_igmp` | low (feature) | ~30 LOC | bond options sparse |
| 12 | `LinkBuilder::vlan` missing `protocol` (802.1Q vs 802.1ad) | low (feature) | ~5 LOC | nlink-lab doesn't need yet |
| 13 | No `LinkBuilder::wireguard` / `LinkBuilder::vrf` | medium (feature) | larger — separate GENL / VRF model | both stay imperative in 158e |
| 14 | No `DeclaredTableBuilder::set(name, \|s\| ...)` for nft sets | low (feature) | larger | sets stay imperative; nlink-lab doesn't use them |
| 15 | `Connection<Route>` has no event subscription (`subscribe`/`events`) | medium (feature) | substantial — new family support | blocks RTNETLINK side of nlink-lab `watch` (Plan 158d) |
| 16 | No `NetworkConfig` `apply_reconcile` parity with `NftablesConfig` | low (ergonomic) | mirror existing | RTNETLINK has less conflict surface |

**Highest leverage:** #1 (the VLAN ifindex race) — fixing this
makes the parent-and-child-in-same-NetworkConfig case usable,
which is a real downstream surprise today.

Everything else is paper-cut to medium-impact and survivable
with the workarounds documented per item.

---

## 1. (HIGH — correctness) `add_link(VlanLink)` parent name→ifindex resolution races with the immediately prior `add_link`

**Severity:** high — silently fails the parent-and-child-in-one-config case for declarative `NetworkConfig` consumers.

**Discovered:** During the CI run for nlink-lab Plan 158e Slice 3's
integration test `slice3_vlan_iface_reapply_is_zero_ops`.

**Repro shape:** in a `NetworkConfig` that declares both a Dummy
(`eth0`) and a VLAN sub-interface (`eth0.42` with `parent="eth0"`),
`apply_diff`'s sequential `for link in &diff.links_to_add {
create_link(conn, link).await? }` loop:

```rust
conn.add_link(DummyLink::new("eth0")).await?;            // ACKed
conn.add_link(VlanLink::new("eth0.42", "eth0", 42)).await?;
//          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
// inside add_link, the VLAN spec carries
// InterfaceRef::Name("eth0"); nlink resolves it via
// `resolve_interface` → `get_link_by_name("eth0")`
// → returns None on the same Connection<Route>
// → Err(Error::InterfaceNotFound { name: "eth0" })
```

**Observed error text** (verbatim from CI):

```
NetworkConfig::apply on 'host': interface not found: eth0
```

…even though the kernel ACKed the dummy's `add_link` immediately
before. The VLAN's internal `get_link_by_name` dump on the same
connection found nothing.

**Hypothesis:** `Connection<Route>` either caches dump results,
or `resolve_interface` goes through a code path that doesn't see
the just-added link until some grace period elapses. Either way,
ACK-after-add doesn't currently guarantee a subsequent
`get_link_by_name` on the same connection reflects the new link.

**Downstream impact:** parent-and-child-in-one-`NetworkConfig` is
unusable. Our Plan 158e Slice 3 integration test had to be
restructured to use a pre-existing veth as the VLAN parent. The
unit test
`network_config_vlan_parent_dummy_declared_first_regardless_of_hashmap_order`
documents that we *declare* the parent correctly first; it's
nlink's add-then-resolve that races.

**Suggested fixes** (pick whichever fits the design):

a. **Retry-with-backoff in `resolve_interface`**: after the first
   miss, sleep 1–5 ms and retry once or twice before failing.
   ~10 LOC at the resolve site. Pragmatic but feels like papering
   over a deeper invariant.

b. **Expose `LinkBuilder::vlan_with_parent_index(idx, vid)`**
   paralleling the imperative `VlanLink::with_parent_index`.
   Downstream code that *knows* the parent's ifindex (e.g.
   because it just created the parent and the create returned
   the index) skips the resolution entirely. Requires the apply
   path to plumb the new index back.

c. **Make `compute_diff` detect VLAN parent-in-config and emit a
   `links_to_modify` op** that retro-fits the parent ifindex into
   the VLAN spec, ordered after the parent create. Most invasive
   but eliminates the race at the design level.

I'd lean toward (a) for the immediate fix and (b) longer-term —
they compose.

---

## 2. (medium — correctness) `NetworkConfig::apply` iterates `links_to_add` in declared order, with no dependency-aware reordering

**Severity:** medium — non-deterministic failure for `HashMap`-built
configs.

**Location:** `crates/nlink/src/netlink/config/apply.rs:118-142`.

**Detail:** `apply_diff` walks `diff.links_to_add` in the order
links were appended via `NetworkConfig::link()`. Downstream code
that builds the config by iterating a `HashMap` (very common —
our `node.interfaces` field is a `HashMap`, like the natural Rust
shape for "key by name") gets non-deterministic order. A VLAN
created before its parent triggers either kernel `ENODEV` (the
cleanly-broken kernel error) or the resolution race above (the
more confusing `Error::InterfaceNotFound` route).

**Downstream workaround:** two-pass iteration inside
`topology_to_network_config` — Pass 1 declares Dummy + Bond +
bond-member master ops; Pass 2 declares VLANs. Regression test
`network_config_vlan_parent_dummy_declared_first_regardless_of_hashmap_order`
runs 4 hash-defeating name pairs.

**Suggested fixes:**

a. **Documentation**: add a paragraph to `NetworkConfig::link`
   rustdoc — kinds with parent dependencies (VLAN, future
   bridge-slave shapes) must be declared *after* their parents in
   the same `NetworkConfig` if both are new.

b. **Topological sort** inside `compute_diff`: read each declared
   link's `DeclaredLinkType` for parent refs
   (`Vlan { parent, .. }`) and reorder `links_to_add` so parents
   come before children. ~40 LOC. Catches the bug at apply time
   without the downstream caller having to know.

The same issue could in principle bite Bond + member shapes —
but in Slice 2, members declared with `.master(bond)` end up in
`links_to_modify` (because veth members already exist as veths
from step 5), which is phase 2 of apply, after the bond creation
in phase 1. So bond ordering happens to be correct by
coincidence. VLAN is the cleanly-broken case.

(Closely related to #1 above. Fix #1 makes #2 less load-bearing,
but the docstring is still worth shipping either way.)

---

## 3. (medium — footgun) `Error::from_errno_ext_ack` silently negates the input

**Severity:** medium — silently produces wrong errno values for
direct callers (tests, mocks, etc.).

**Location:** `crates/nlink/src/netlink/error.rs:321-333`.

```rust
pub fn from_errno_ext_ack(
    errno: i32,
    ext_ack: Option<String>,
    ext_ack_offset: Option<u32>,
) -> Self {
    let message = io::Error::from_raw_os_error(-errno).to_string();
    Self::Kernel {
        errno: -errno,   // <-- negates the input
        ...
    }
}
```

**Convention:** the factory is intended to receive the kernel's
signed errno as it appears in `nlmsgerr.error` (which is negative
— `-EEXIST = -17`); after the internal negation the stored field
is positive `17`, which is what programmers expect from
`.errno()`.

**Footgun:** a direct caller (e.g. me, writing a unit test for
`Error::ext_ack` chain walks) reads `errno: i32` in the signature
and reasonably passes `1` thinking "POSIX EPERM". Stored value
becomes `-1`. `.errno()` returns `Some(-1)`.

Real impact from nlink-lab's `crates/nlink-lab/src/error.rs::tests`:

```rust
let kernel = nlink::Error::from_errno_ext_ack(1, ..., Some(16));
let lab_err = Error::Namespace { ..., source: kernel };
assert_eq!(lab_err.errno(), Some(-1));   // <-- counter-intuitive
```

I had to write `Some(-1)` instead of the intuitive `Some(1)`.

**Suggested fixes** (pick one):

a. **Rename the parameter** to `errno_signed: i32` or
   `errno_negated: i32` — convention lives in the signature.

b. **Document it**: one sentence on the factory rustdoc — *"Pass
   the kernel's negative-form errno; the factory negates it
   internally to produce the standard positive form on
   `Self::Kernel.errno`."*

c. **Normalize**: change the body to `errno: -errno.abs()` so both
   `1` and `-1` produce stored `17` for EEXIST. Slightly
   opinionated; eliminates the footgun entirely.

Same applies to `from_errno_with_context_ext_ack`. The non-`_ext_ack`
variants (`from_errno`, `from_errno_with_context`) inherit the
same convention indirectly.

---

## 4. (medium — footgun) `Box<nlink::Error>` as `#[source]` breaks the chain-walk downcast

**Severity:** medium — silent breakage for downstream
`Error::ext_ack`-style chain-walk accessors.

**Background:** In nlink-lab Plan 158b we added `Error::ext_ack`
that walks the source chain via `std::error::Error::source` and
does `src.downcast_ref::<nlink::Error>()` at each step (matching
the shape of nlink 0.18's own `Error::ext_ack` inherent
accessor).

**The trap:** clippy (`result_large_err`) flagged our outer
`Error` enum as too large because the `Namespace { source:
nlink::Error }` variant carries the ~200-byte `nlink::Error`
inline. We tried boxing it: `source: Box<nlink::Error>`. The
chain walk silently stopped finding the inner `nlink::Error`:

- thiserror's generated `source() -> &dyn Error` for
  `Box<nlink::Error>` returns the `Box<nlink::Error>` as
  `&dyn Error`.
- `downcast_ref::<nlink::Error>()` on that returns `None` because
  the concrete type is `Box<nlink::Error>`, not `nlink::Error`.

Result: `err.ext_ack()` returns `None` even though the chain
*does* contain a kernel error. Tests caught it. We backed out
the box and crate-allowed the `result_large_err` lint.

**This isn't strictly nlink's bug** — it's how Rust's `downcast`
+ thiserror's `#[source]` expansion compose. But it's surprising
enough that a one-paragraph note in `Error::Kernel`'s rustdoc
would save the next consumer the same debug cycle:

> Consumers boxing this error in a `#[source]` field break the
> `downcast_ref::<nlink::Error>()` chain-walk pattern that
> `Error::ext_ack` / `errno` / `ext_ack_offset` rely on, because
> the concrete type behind `&dyn Error` becomes
> `Box<nlink::Error>` rather than `nlink::Error`. Carry the
> error inline if you want the inherent accessors to work
> through your wrapper, or implement the chain walk manually
> with `match src.downcast_ref::<Box<nlink::Error>>()` first.

---

## 5. (low — ergonomic) `ConfigDiff` has no inherent `.apply()` method

**Severity:** low — naming asymmetry with `NftablesDiff`.

**Surface:** `NftablesDiff::apply` and `NftablesDiff::apply_reconcile`
are inherent methods on the diff struct (`nftables/config/diff.rs`).
`ConfigDiff` (the RTNETLINK one) has neither.

**Consequence:** consumers writing the intuitive chain

```rust
cfg.diff(&conn).await?.apply(&conn, opts).await?;
```

get a method-not-found error. Today they have to either go
through `cfg.apply(&conn)` (which re-runs `compute_diff`
internally — one wasted dump round-trip) or import the private
`config::apply::apply_diff` free function.

**Suggested fix:** add a thin wrapper on the diff struct:

```rust
impl ConfigDiff {
    pub async fn apply(
        &self,
        conn: &Connection<Route>,
        opts: ApplyOptions,
    ) -> Result<ApplyResult> {
        apply::apply_diff(self, conn, opts).await
    }
}
```

Matches `NftablesDiff`'s shape and the natural method-chain
ergonomic.

---

## 6. (low — ergonomic) `apply::apply_diff` free function not re-exported

**Severity:** low — couples to #5.

**Location:** `crates/nlink/src/netlink/config/mod.rs:46-51`.

```rust
mod apply;             // <-- private
pub use apply::{ApplyOptions, ApplyResult};   // only these two
```

The free `apply_diff(&ConfigDiff, &Connection<Route>, ApplyOptions)
-> Result<ApplyResult>` (`apply.rs:98`) is the natural primitive
for consumers that already hold a `ConfigDiff`. Today it's only
reachable through `NetworkConfig::apply` (re-runs the diff).

**Suggested fix:** `pub use apply::apply_diff;` in `config/mod.rs`.
Or just add #5's inherent method, which routes through this
internally and makes the free function unnecessary publicly.

(I noted this primarily because our `compute_layered_diff` helper
would have benefited from being able to compute the diff once,
render it, and then commit — without paying for `compute_diff`
twice.)

---

## 7. (low — ergonomic) `ApplyOptions` has no builder methods

**Severity:** low — paper-cut.

**Location:** `crates/nlink/src/netlink/config/apply.rs:28-43`.

```rust
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    pub dry_run: bool,
    pub continue_on_error: bool,
    pub purge: bool,
}
```

Construction today requires struct-literal syntax:

```rust
ApplyOptions {
    dry_run: true,
    continue_on_error: false,
    ..Default::default()
}
```

Compare `NftablesConfig::ReconcileOptions` (Plan 163 in 0.16
made it builder-shaped to enable the `#[non_exhaustive]` semver
hygiene story):

```rust
ReconcileOptions::default()
    .max_retries(5)
    .backoff(Duration::from_millis(50))
```

**Suggested fix:** mirror `ReconcileOptions` — add
`#[non_exhaustive]` + `pub fn with_dry_run(self, b: bool) -> Self`,
`with_continue_on_error`, `with_purge`. Same pattern, ~15 LOC,
future-proof.

---

## 8. (low — ergonomic) `RouteBuilder::new` doesn't accept the `"default"` magic string

**Severity:** low — needs downstream translation.

**Location:** `crates/nlink/src/netlink/config/types.rs:640-670`.

`RouteBuilder::new(dst: &str) -> Result<Self, RouteParseError>`
parses `dst` as CIDR (must contain `/`). The string `"default"`
(the canonical iproute2 idiom for `0.0.0.0/0` or `::/0`) is
rejected.

**Workaround we shipped:** `crates/nlink-lab/src/deploy.rs::push_route`
translates `"default"` to `"0.0.0.0/0"` or `"::/0"` based on the
family of the gateway IP.

**Suggested fix:** mirror `Ipv4Route::default_route()` /
`Ipv6Route::default_route()` (Plan 184 in 0.18) on the
declarative builder:

```rust
impl RouteBuilder {
    pub fn default_v4() -> Self { ... }   // 0.0.0.0/0
    pub fn default_v6() -> Self { ... }   // ::/0
}
```

~10 LOC. Avoids the family-inference question that a bare
`"default"` magic string would raise.

---

## 9. (low — feature) No `Serialize` derive on `ConfigDiff` / `NftablesDiff`

**Severity:** low — affects machine-readable diff consumers.

**Context:** nlink-lab Plan 158f Phase 2 added an
`apply --check --json` envelope that includes the layered diff.
The envelope is documented at `docs/json-schemas/layered-diff.schema.json`.
The lab's own `TopologyDiff` carries `#[derive(Serialize)]` and
serializes natively. The two upstream diffs (`ConfigDiff` +
`NftablesDiff`) don't — we fall back to including a
`layered_summary: String` field carrying the rendered `Display`
output.

**Suggested fix:** add a `serde` feature flag on the nlink crate;
gate `#[cfg_attr(feature = "serde", derive(Serialize))]` on the
public diff types (and their leaf field types: `DeclaredLink`,
`DeclaredAddress`, `DeclaredRoute`, `DeclaredQdisc`, etc.).
Downstream consumers opt in.

Same applies to `ApplyResult`, `ApplyError`, `ReconcileReport`.

---

## 10. (low — feature gap) `LinkBuilder::vxlan` missing `.local()` / `.port()` / `.underlay_dev()`

**Severity:** low — keeps Vxlan on the imperative path in
nlink-lab.

**Location:** `crates/nlink/src/netlink/config/types.rs::LinkBuilder`.

Current `LinkBuilder::vxlan(vni)` + `.vxlan_remote(addr)` covers
VNI + remote endpoint only.

Imperative `VxlanLink` (in `netlink/link.rs`) exposes:

- `.local(IpAddr)` — tunnel source IP
- `.port(u16)` — UDP encap port (default 4789)
- `IFLA_VXLAN_LINK` field for the underlay parent device

nlink-lab's `InterfaceConfig` carries `local: Option<String>`
and `port: Option<u16>`, surfaced from NLL syntax. Without
declarative coverage, Vxlan stays imperative (step 6 in our
deploy), and re-applies on Vxlan resources are not idempotent.

**Suggested addition:**

```rust
impl LinkBuilder {
    pub fn vxlan_local(self, addr: IpAddr) -> Self { ... }
    pub fn vxlan_port(self, port: u16) -> Self { ... }
    pub fn vxlan_underlay_dev(self, name: &str) -> Self { ... }
}
```

Tiny upstream PR; would let our Plan 158e Slice 4 fold VXLAN
creation into the declarative path.

---

## 11. (low — feature gap) `LinkBuilder::bond` bond options are sparse

**Severity:** low — niche.

**Coverage today** (per the 158e Slice 2 audit):

- ✅ `bond_mode`
- ✅ `miimon`
- ✅ `xmit_hash_policy`
- ✅ `min_links`

**Missing**:

- `ad_select` (LACP selection logic — `stable`/`bandwidth`/`count`)
- `lacp_rate` (`slow`/`fast`)
- `downdelay`
- `updelay`
- `resend_igmp`

nlink-lab doesn't currently expose these in its NLL syntax, so we
don't bleed downstream. But for users who need richer bond
shapes, the gap means dropping back to the imperative `BondLink`
builder.

---

## 12. (low — feature gap) `LinkBuilder::vlan` missing `protocol` (802.1Q vs 802.1ad)

**Severity:** very low — most users default to 802.1Q.

`VlanLink` (imperative) has a `protocol: Option<VlanProtocol>`
field. `LinkBuilder::vlan(parent, vid)` doesn't surface it. For
Q-in-Q (802.1ad) and EtherType selection, downstream consumers
fall back to imperative.

**Suggested addition:** `LinkBuilder::vlan_protocol(VlanProtocol)`.

---

## 13. (medium — feature gap) No `LinkBuilder::wireguard` or `LinkBuilder::vrf`

**Severity:** medium — keeps two significant resource kinds
entirely imperative for declarative consumers.

**WireGuard.** Lives in a separate GENL family (`Wireguard`),
not RTNETLINK, so it doesn't naturally fit `NetworkConfig`. A
coherent design would either:

- expose a parallel `WireguardConfig` type with its own
  diff/apply, or
- have `LinkBuilder::wireguard()` create just the link (a
  `wg`-kind RTNETLINK link) and require a separate imperative
  pass for peer/key configuration via `Connection<Wireguard>`.

We use the second pattern downstream — WG link addresses go
through `NetworkConfig` (Plan 158e Slice 1), peer/key config
stays imperative (step 10d). But the WG link itself is *also*
still imperative because `LinkBuilder` doesn't model `Wireguard`
as a kind. Adding it would let us at least declare the link in
`NetworkConfig`, narrowing the imperative surface.

**VRF.** Just an RTNETLINK link kind. `DeclaredLinkType`
(`config/types.rs:159-183`) lists Physical/Dummy/Veth/Bridge/VLAN/VXLAN/Macvlan/Bond/IFB;
no VRF variant. The runtime `VrfLink` exists in `link.rs` so the
wire format is known.

**Suggested addition:**

```rust
pub enum DeclaredLinkType {
    ...
    Vrf { table: u32 },
}
impl LinkBuilder {
    pub fn vrf(mut self, table: u32) -> Self { ... }
}
```

For VRF, also useful: `LinkBuilder::master(name)` already exists
for bond-style enslavement, which would let interfaces declare
themselves as VRF members declaratively too (kernel uses the same
`IFLA_MASTER` attribute).

---

## 14. (low — feature gap) No declarative nft sets

**Severity:** low — nlink-lab doesn't use nft sets, but the
surface is uneven.

**Detail:** `DeclaredTableBuilder` exposes `.chain(name, |c| ...)`,
`.rule(...)`, `.flowtable(...)`, but no `.set(name, |s| ...)`.
The imperative `Connection<Nftables>::add_set` exists for
downstream code that wants sets.

`nlink::netlink::nftables::types::SetKeyType` covers
Ipv4Addr / Ipv6Addr / EtherAddr / InetService / IfIndex / Mark.
The missing piece is the declarative integration.

Lower priority for nlink-lab specifically — flagging in case
other downstreams want it.

---

## 15. (medium — feature gap) `Connection<Route>` has no event subscription

**Severity:** medium — blocks RTNETLINK-side drift detection in
nlink-lab.

**Context:** nlink-lab Plan 158d is the `nlink-lab watch`
subcommand that streams nftables events per namespace via
`Connection<Nftables>::subscribe_all_with_resync`. Plan 158d
audit (committed as `docs/plans/158d-watch-nft-events.md`)
documents this gap explicitly:

> Two consequences for Plan 158d:
> 1. The watch command covers nftables drift only.
> 2. A future ask to upstream could add
>    `Connection<Route>::subscribe(RouteGroup::All)` + a typed
>    `RouteEvent` enum, mirroring the nftables shape.

**Mirroring shape** (sketch):

```rust
#[non_exhaustive]
pub enum RouteEvent {
    NewLink(LinkMessage), DelLink(LinkMessage),
    NewAddr(AddressMessage), DelAddr(AddressMessage),
    NewRoute(RouteMessage), DelRoute(RouteMessage),
    NewNeigh(NeighborMessage), DelNeigh(NeighborMessage),
}

impl Connection<Route> {
    pub fn subscribe(&mut self, groups: &[RouteGroup]) -> Result<()>;
    pub fn events(&self) -> EventSubscription<'_, Route>;
    pub fn into_events_with_resync<F>(self, snapshot: F) -> OwnedResyncStream;
}
```

Same pattern as nftables (Plan 185 in nlink 0.18). Substantial
work — new protocol-family support — but unlocks a meaningful
capability surface for downstream consumers.

For drift-detection on RTNETLINK without this, our only option is
periodic polling via `NetworkConfig::diff(&conn)` per namespace
per interval. Documented as the fallback in 158d.

---

## 16. (low — ergonomic) `NetworkConfig` lacks `apply_reconcile` parity with `NftablesConfig`

**Severity:** low — RTNETLINK has less conflict surface than
nftables.

`NftablesDiff::apply_reconcile(&conn, opts)` provides bounded
retry-on-conflict with exponential backoff for the
`Error::is_busy()` / `Error::is_try_again()` predicates.
RTNETLINK ops have fewer transient-conflict failure modes (no
equivalent of the batch-end races nftables historically had),
but VRF table-allocation, neighbor cache pressure, and similar
edge cases could still benefit from a retry knob.

Lowest-priority item on this list — flagged for completeness.

---

## Wishlist — capabilities that would change the integration story

These aren't bugs; they're "the 158 arc would have been simpler
if these existed." Roughly ordered by impact-to-effort ratio.

### W1. Dump-cache invalidation hook on `Connection<P>`

Connects to issue #1 above. The race I observed in `add_link` →
`get_link_by_name` suggests `Connection<Route>` may carry stale
state. A `Connection::invalidate_cache()` (or, alternatively, a
hard guarantee that ACK-after-add semantically commits to all
subsequent same-connection queries) would let downstream
consumers reason about ordering without retry loops.

### W2. `Connection<Route>::subscribe` + `RouteEvent`

Issue #15 above. Closes the RTNETLINK side of the nlink-lab
`watch` story.

### W3. `LinkBuilder::wireguard` + `LinkBuilder::vrf`

Issue #13 above. Folds two large remaining imperative surfaces
into the declarative path.

### W4. `serde` feature flag on diff types

Issue #9 above. Lets downstream JSON-output consumers serialize
upstream diffs natively without the Display-string fallback.

### W5. `Connection::<P>::lazy()` constructor with deferred socket creation

Today every `Connection::<P>::new()` opens a fresh kernel socket.
nlink-lab opens many transient connections per node per apply
(one for Route, one for Nftables, one for Wireguard, …). A
50-node lab makes ~150 socket-open syscalls per deploy.

`ConnectionPool` (Plan 159+ in nlink) addresses this but isn't
yet adopted in nlink-lab — partly because each namespace needs
its own pool (the pool isn't namespace-aware). A
`Connection::lazy()` that defers socket creation until the first
I/O would let nlink-lab construct connections speculatively
without paying the syscall cost until needed.

Low-priority; mentioned in case it composes with future pool
work.

### W6. `LinkChanges::Display`

When `ConfigDiff::links_to_modify` carries
`Vec<(String, LinkChanges)>`, the only way to render *what*
changed is to walk `LinkChanges` field-by-field. A `Display`
impl that emits a compact diff line
(`"eth0: mtu 1500 → 9000, state down → up"`) would round out the
Display-for-diff story Plan 183 in 0.18 started.

### W7. `Connection::<P>::span()` for tracing

Many of nlink-lab's `Error::deploy_failed(format!("…: {e}"))`
wrappers add the same context that `Connection::<P>` operations
could span via `#[tracing::instrument]`. Some methods already do
(e.g. `from_errno_with_context`). Universal span coverage would
let consumers `RUST_LOG=nlink=debug` and see the exact operation
that failed without per-call manual wrapping.

Plan 174 in nlink 0.17 added some of this for the integration-test
path; extending it to the public surface would close the loop.

### W8. `del_table` / `del_chain` / `del_rule` idempotent variants

`Connection::<Nftables>::del_table("foo", Family::Inet).await`
returns an error if the table doesn't exist. Downstream code
universally ignores this via
`let _ = conn.del_table(...).await;` or `if let Err(e) = ... {
tracing::warn!(...); }`. A `del_table_if_exists` variant (or a
`del_table` that returns `Ok(false)` instead of erroring on
ENOENT) would clean up the pattern. Same for `del_chain`,
`del_rule`.

### W9. Macvlan mode coverage on `LinkBuilder::macvlan_mode`

`LinkBuilder::macvlan_mode(MacvlanMode)` covers
Bridge / Private / Vepa / Passthru per the 158e audit. The
kernel also defines `Source` mode (source-MAC filtering). If/when
nlink-lab grows source-filter support, this gap matters.

---

## Documentation suggestions

Things that would have saved me debug time, ordered by likely
savings:

### D1. VLAN-parent ordering / ifindex-resolution caveat

`NetworkConfig::link` rustdoc should mention: "LinkBuilder kinds
with parent dependencies (VLAN today, possibly future
bridge-slave shapes) must be declared *after* their parents in
the same `NetworkConfig`, AND the parent must already exist in
the kernel at apply time. Creating both parent and child in the
same `NetworkConfig::apply` is not currently reliable — see issue
X."

### D2. `Box<Error>` source downcast trap

`Error::Kernel` variant rustdoc should note: "If you wrap this
error in a `#[source]` field, carry it inline rather than boxed.
Boxing breaks `downcast_ref::<nlink::Error>()` chain-walk
patterns that `Error::ext_ack` / `errno` / `ext_ack_offset` rely
on (because the concrete type behind `&dyn Error` becomes
`Box<nlink::Error>` rather than `nlink::Error`). Consumers boxing
for `result_large_err` ergonomics must implement the chain walk
manually."

### D3. `from_errno_ext_ack` sign convention

Either #3's rename/normalize, or a one-sentence rustdoc.

### D4. `InterfaceRef::Name` namespace pitfall

The docstring on `VlanLink::with_parent_index` already says:
*"This is the namespace-safe variant that avoids reading from
/sys/class/net/."* If that's accurate (the name-based variant
reads `/sys/class/net/<name>/ifindex`?), it's a real namespace
pitfall — `/sys/class/net` shows the host's interfaces from
inside many namespace setups. Worth a note on `VlanLink::new`
saying "prefer `with_parent_index` from inside namespaces."

If the name-based variant actually goes through
`resolve_interface` (which uses netlink, namespace-correct), then
the docstring on `with_parent_index` is misleading and should be
reworded.

### D5. Default `ApplyOptions` semantics

What does `ApplyOptions::default()` do on failure? Today:
`continue_on_error: false` → first error propagates as `Err`.
`dry_run: false` → real changes. `purge: false` → no removals.
This is the right default but isn't surfaced anywhere obvious —
a single example in the module docstring would help.

### D6. The two diff shapes: `ConfigDiff::summary()` vs `Display`

`ConfigDiff` carries both a `summary() -> String` method (per the
earlier audit at line 87) and `Display` (Plan 183 in 0.18). What
distinguishes them? When should consumers prefer one over the
other? A one-line note on each clarifying the relationship would
help — I went with `Display` for nlink-lab's `LayeredDiff` and
remain unsure whether the older `.summary()` is still the
recommended path for any case.

---

## What landed great in 0.18 — for context

Just so this isn't all "things missing": the 0.18 release that
landed in response to nlink-lab's earlier upstream-asks report
(`nlink-upstream-asks.md`) absolutely unblocked the 158 arc.
Specifically:

- **Plan 180 → `DeclaredChainBuilder::chain_type`** unblocked
  declarative NAT chains (Plan 158a Phase 2 ships unchanged).
- **Plan 181 → `list_*_in` filtered dumps** let our resync
  snapshot in Plan 158d enumerate per-table without client-side
  filtering.
- **Plan 182 → `Error::ext_ack()` accessor** is the exact shape
  we mirrored in `nlink_lab::Error::ext_ack` for Plan 158b.
- **Plan 183 → `Display for NftablesDiff / ConfigDiff`** is the
  renderer Plan 158f's `LayeredDiff::Display` delegates to.
- **Plan 184 → `Ipv4Route::default_route()` /
  `Ipv6Route::default_route()`** killed the `"0.0.0.0"` literal
  idiom at four nlink-lab call sites.
- **Plan 185 → `subscribe_all_with_resync(factory)`** shrunk
  Plan 158d's per-namespace plumbing from ~60 LOC to ~5 (when
  it ships).

That was already substantial, with `chain_type` in particular
being a delight to use. The items in this report are the next
round.

---

## Triage at a glance

| Category | Count | High-leverage items |
|----------|-------|---------------------|
| Bugs (correctness) | 2 | #1 VLAN parent ifindex race, #2 declared-order iteration |
| Footguns | 2 | #3 errno sign, #4 Box source downcast |
| Ergonomic gaps | 4 | #5–#8 |
| Feature gaps | 5 | #10–#14 (Vxlan / bond / vlan protocol / WG+VRF / sets) |
| Capability gaps | 2 | #15 Route events, #16 reconcile parity |
| Wishlist | 9 | W1–W9 |
| Docs | 6 | D1–D6 |

**Most actionable: #1, #3, #4, D1, D2, D3.** Those would close
the friction points I encountered most often during the arc.

I'm happy to open upstream PRs for any of these if it helps, or
if there's anything to clarify on the downstream impact. Thanks
again for the 0.18 round — that genuinely shipped what was
asked for.
