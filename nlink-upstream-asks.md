# Upstream asks for nlink (from nlink-lab maintainer)

**Audience:** an LLM (or human) working on `/home/mpardo/git/rip`
(the nlink netlink library, currently at `0.17.0`).
**Author:** nlink-lab maintainer; nlink-lab is the
namespace-based network-lab engine that uses nlink as its
sole netlink backend.
**Date:** 2026-05-27
**nlink version reviewed:** `0.17.0`.

---

## TL;DR — what to do

| # | Ask | Effort | Blocking? |
|---|-----|--------|-----------|
| 1 | Add `chain_type` field + builder to `DeclaredChain` / `DeclaredChainBuilder` | ~30 LOC + 2 tests | **YES — blocks nlink-lab Plan 158a Phase 2 (NAT reconcile)** |
| 2 | Add server-side table+family filter to `list_chains` and `list_flowtables` to mirror `list_rules` | ~20 LOC + 2 tests | No (nice-to-have for nlink-lab Plan 158d resync) |

(One earlier "ask" — `PerHostLimiter::reconcile` — was a false
alarm. It already exists at `crates/nlink/src/netlink/ratelimit.rs:749`.
A stale comment in nlink-lab's `deploy.rs:2956-2961` claimed it was
missing; I'll fix that on my side.)

If you can only do one of these, do #1.

---

## Context

`nlink-lab` is preparing to upgrade from `nlink = "0.15.1"` to
`nlink = "0.17"` and adopt the declarative
`NftablesConfig::diff(&conn).apply(&conn)` reconcile path
(0.16's Plan 157b / 0.17's Plan 178). The migration plan is
`docs/plans/158a-nftables-reconcile.md` in the nlink-lab
repo.

Doing this lets nlink-lab replace its current "delete the
whole table, rebuild from scratch" reconcile on every change
to firewall/NAT rules with per-rule USERDATA-keyed reconcile —
zero kernel calls on no-op re-apply, no transient empty-chain
window, atomic batch, and foreign-rule survival (rules without
the `nlink:` USERDATA prefix are left untouched). Big win.

While planning the migration I audited the 0.17 surface and
found one real blocker and one ergonomic-symmetry gap. Both
are small.

---

## Ask 1 (BLOCKING) — `DeclaredChainBuilder::chain_type(ChainType)`

### Current state

`DeclaredChain` carries `name`, `hook`, `priority`, `policy`
but **not** `chain_type`. The imperative runtime `Chain`
type does carry it (used to set `NFTA_CHAIN_TYPE` to
`"nat"`/`"filter"`/`"route"`), but the declarative side
doesn't surface or thread it.

Citations:

- `crates/nlink/src/netlink/nftables/config/types.rs:216-221`
  — `DeclaredChain` struct definition (no `chain_type`
  field).
- `crates/nlink/src/netlink/nftables/config/types.rs:244-289`
  — `DeclaredChainBuilder` impl (only `.hook()`, `.priority()`,
  `.policy()` exposed).
- `crates/nlink/src/netlink/nftables/config/apply.rs:100-112`
  — apply path reconstructs the runtime `Chain` from
  `DeclaredChain` without setting `chain_type`:

  ```rust
  for (table_name, family, declared) in &self.chains_to_add {
      let mut chain = Chain::new(table_name, declared.name()).family(*family);
      if let Some(h) = declared.hook() {
          chain = chain.hook(h);
      }
      if let Some(p) = declared.priority() {
          chain = chain.priority(p);
      }
      if let Some(pol) = declared.policy() {
          chain = chain.policy(pol);
      }
      tx = tx.add_chain(chain);
  }
  ```

- `crates/nlink/src/netlink/nftables/types.rs:66-82` —
  `ChainType` enum (`Filter`, `Nat`, `Route`).
- `crates/nlink/src/netlink/nftables/types.rs:479-525` —
  imperative `Chain::chain_type(ChainType)` builder method
  (the model to mirror).

### Why nlink-lab needs it

NAT base chains hook at `prerouting`/`postrouting` and must
declare `chain_type "nat"` in the kernel — otherwise the
chain is created as `chain_type "filter"`, NAT verdicts
(`masquerade`, `snat`, `dnat`) refuse to load with EOPNOTSUPP,
and the whole batch rolls back.

nlink-lab today builds NAT chains imperatively
(`crates/nlink-lab/src/deploy.rs:1827-1922`); migrating the
whole `apply_firewall` + `apply_nat` path to a single
`NftablesConfig::diff().apply()` requires declaratively
expressing NAT chains.

### Proposed implementation

`crates/nlink/src/netlink/nftables/config/types.rs`:

```rust
// Inside DeclaredChain struct (around line 220):
pub struct DeclaredChain {
    name: String,
    hook: Option<Hook>,
    priority: Option<Priority>,
    policy: Option<Policy>,
    chain_type: Option<ChainType>,   // NEW
}

// DeclaredChainBuilder impl (around line 280):
impl DeclaredChainBuilder {
    /// Set the chain type — `ChainType::Filter` (default for
    /// base chains, kernel-side), `ChainType::Nat` (required
    /// for prerouting/postrouting NAT chains), or
    /// `ChainType::Route` (output routing decisions).
    ///
    /// Mirrors [`Chain::chain_type`] on the imperative side.
    pub fn chain_type(mut self, chain_type: ChainType) -> Self {
        self.chain_type = Some(chain_type);
        self
    }
}

// And matching getter:
impl DeclaredChain {
    pub fn chain_type(&self) -> Option<ChainType> {
        self.chain_type
    }
}
```

`crates/nlink/src/netlink/nftables/config/apply.rs`,
around line 109 (inside the `chains_to_add` loop):

```rust
        if let Some(pol) = declared.policy() {
            chain = chain.policy(pol);
        }
        if let Some(ct) = declared.chain_type() {        // NEW
            chain = chain.chain_type(ct);                // NEW
        }
        tx = tx.add_chain(chain);
```

That's the whole change. Estimated ~30 LOC including
imports + the builder docstring.

### Tests

#### Unit test — declarative path emits the right attribute

In `crates/nlink/src/netlink/nftables/config/tests.rs`
(or wherever the existing declarative tests live — look at
how `chain` policy/priority round-trip tests are structured):

```rust
#[test]
fn declared_chain_type_round_trips_to_runtime() {
    use crate::netlink::nftables::config::NftablesConfig;
    use crate::netlink::nftables::types::{ChainType, Family, Hook, Priority};

    let cfg = NftablesConfig::new().table("nat-test", Family::Inet, |t| {
        t.chain("postrouting", |c| {
            c.hook(Hook::Postrouting)
                .priority(Priority::SrcNat)
                .chain_type(ChainType::Nat)
        })
    });

    // Walk the declared tree and assert chain_type survives.
    let table = cfg.tables().first().unwrap();
    let chain = table.chains().first().unwrap();
    assert_eq!(chain.chain_type(), Some(ChainType::Nat));
}
```

#### Wire-roundtrip unit test — apply produces NFTA_CHAIN_TYPE

Mirror the pattern used for the existing
"chain policy serializes to NFTA_CHAIN_POLICY" test (search
the test module for `NFTA_CHAIN_POLICY` to find it). Capture
the `NftablesDiff::apply` transaction bytes (without sending
to a real kernel), parse them, and assert the
`NFTA_CHAIN_TYPE` attribute carries the string `"nat"`.

#### Root-gated integration test

In `crates/nlink/tests/integration/nftables_reconcile.rs`
(the existing 7-test file at
`tests/integration/nftables_reconcile.rs`), add an 8th
scenario:

```rust
/// Declared NAT chain round-trips through the kernel with
/// the right chain_type — without this the kernel rejects
/// `masquerade` / `snat` / `dnat` verdicts with EOPNOTSUPP
/// inside the batch.
#[tokio::test(flavor = "multi_thread")]
async fn nat_chain_chain_type_round_trips() {
    nlink::require_root!();
    nlink::require_modules!("nf_tables");

    let conn = Connection::<Nftables>::new().unwrap();

    // Clean slate.
    let _ = conn.del_table("nlink-nat-test", Family::Inet).await;

    let cfg = NftablesConfig::new().table("nlink-nat-test", Family::Inet, |t| {
        t.chain("postrouting", |c| {
            c.hook(Hook::Postrouting)
                .priority(Priority::SrcNat)
                .chain_type(ChainType::Nat)
        })
        .rule_keyed("postrouting", "nat-test:0", |r| {
            r.match_saddr_v4("10.0.0.0".parse().unwrap(), 24)
                .masquerade()
        })
    });

    cfg.diff(&conn).await.unwrap().apply(&conn).await.unwrap();

    // Dump back and verify chain_type was set to Nat.
    let chains = conn.list_chains().await.unwrap();
    let pr = chains
        .iter()
        .find(|c| c.name == "postrouting" && c.table == "nlink-nat-test")
        .expect("chain must exist");
    assert_eq!(pr.chain_type, Some(ChainType::Nat));

    // Idempotent re-apply yields zero changes (existing 0.17
    // diff invariant — guard it for this code path too).
    let diff2 = cfg.diff(&conn).await.unwrap();
    let report2 = diff2.apply(&conn).await.unwrap();
    assert_eq!(report2, 0);

    let _ = conn.del_table("nlink-nat-test", Family::Inet).await;
}
```

This test runs under the existing
`.github/workflows/integration-tests.yml` privileged-runner
workflow (the one shipping 20 root-gated tests from Plan 166).
No new CI infrastructure required.

### Acceptance

- `cargo test -p nlink --lib config::tests::declared_chain_type_round_trips_to_runtime` passes.
- `cargo test -p nlink --lib config::tests::<wire_roundtrip_test_name>` passes.
- The integration test passes under root (`sudo cargo test -p nlink --test integration nat_chain_chain_type_round_trips`).
- CHANGELOG entry under `[Unreleased] → Added`:
  > `DeclaredChainBuilder::chain_type(ChainType)` — required for
  > declarative NAT chain reconcile via `NftablesConfig`. Mirrors
  > the imperative `Chain::chain_type` builder method. Without
  > this, declared NAT chains defaulted to `ChainType::Filter`
  > and NAT verdicts (`masquerade`/`snat`/`dnat`) refused to
  > load.
- One-line note in the migration guide
  `docs/migration_guide/0.17.0-to-0.18.0.md` (or whichever
  is current) under "Added".

### Suggested PR title

> `feat(nftables): DeclaredChainBuilder::chain_type for declarative NAT chains`

---

## Ask 2 (NICE-TO-HAVE) — server-side table+family filter on `list_chains` / `list_flowtables`

### Current state

`list_rules(table, family)` filters server-side by sending
`NFTA_RULE_TABLE` in the dump request — kernel returns only
matching rules. But `list_chains()` and `list_flowtables()`
take **no parameters** and dump every chain/flowtable across
every family. Consumers filter client-side.

Citations:

- `crates/nlink/src/netlink/nftables/connection.rs:293-314`
  — `list_chains()` (no args, sends `nfgen_family: 0`).
- `crates/nlink/src/netlink/nftables/connection.rs:187-209`
  — `list_flowtables()` (no args, sends `nfgen_family: 0`).
- `crates/nlink/src/netlink/nftables/connection.rs:376-394`
  — `list_rules(table, family)` — the existing pattern to
  mirror, sending `nfgen_family: family.into()` and
  `NFTA_RULE_TABLE` attribute.

### Why nlink-lab cares

For Plan 158d's nftables-multicast watch mode, an ENOBUFS
resync needs to snapshot per-namespace nftables state. The
snapshot enumerates tables → chains → rules → flowtables and
synthesizes `Resynced(NewTable/NewChain/NewRule/NewFlowtable)`
events. Today the chains and flowtables dumps return state
across every table+family in the namespace, and the watcher
has to filter client-side.

This is a small efficiency hit on the resync path, not a
correctness issue. nlink-lab can ship 158d without this and
filter client-side. But the asymmetry between
`list_rules(table, family)` (filtered) and
`list_chains()` / `list_flowtables()` (unfiltered) is
ergonomic-disasterous if someone learns one and assumes the
other matches.

### Proposed implementation

Two options:

**Option A (recommended): add new filtered methods, keep the unfiltered ones**

```rust
// crates/nlink/src/netlink/nftables/connection.rs

/// List all chains. Dumps every family + table — for
/// per-table results, use [`list_chains_in`].
pub async fn list_chains(&self) -> Result<Vec<ChainInfo>> { … existing … }

/// List chains in a specific table+family. Server-side
/// filtered via `NFTA_CHAIN_TABLE` + `nfgen_family` — more
/// efficient than `list_chains().filter(...)` on hosts with
/// many tables.
pub async fn list_chains_in(&self, table: &str, family: Family) -> Result<Vec<ChainInfo>> {
    let mut builder =
        MessageBuilder::new(nft_msg_type(NFT_MSG_GETCHAIN), NLM_F_REQUEST | NLM_F_DUMP);
    let nfgenmsg = NfGenMsg::new(family);
    builder.append(&nfgenmsg);
    builder.append_attr_str(NFTA_CHAIN_TABLE, table);

    let responses = self.nft_dump(builder).await?;
    let mut chains = Vec::new();
    for (family_byte, payload) in &responses {
        let family = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
        if let Some(chain) = parse_chain(payload, family) {
            chains.push(chain);
        }
    }
    Ok(chains)
}

// Same shape for list_flowtables_in (using NFTA_FLOWTABLE_TABLE).
```

**Option B: extend existing signatures with optional filters**

```rust
pub async fn list_chains(&self, table: Option<&str>, family: Option<Family>) -> Result<Vec<ChainInfo>>;
```

Breaking but tidier. Probably wait for a 0.18 cycle if you'd
take this route.

Pick whichever matches your API direction. I'd lean to
Option A — backwards-compatible, mirrors the existing
naming convention used by other "filter-by-table" helpers
in the codebase.

### Tests

For each new method:

- **Unit test**: build the dump request, assert the
  `NFTA_*_TABLE` attribute + family are present in the
  emitted bytes.
- **Integration test (root-gated)**: create two tables in
  the same namespace, list chains in just one via the new
  helper, assert only the matching subset comes back.

### Acceptance

- New methods `list_chains_in` + `list_flowtables_in` exist
  on `Connection<Nftables>`.
- Both have rustdoc explaining the relationship with the
  unfiltered counterparts.
- CHANGELOG entry under `[Unreleased] → Added`.

### Suggested PR title

> `feat(nftables): list_chains_in / list_flowtables_in — server-side filter mirror of list_rules`

---

## Background: why nlink-lab is upgrading

For context. Not actionable.

### What nlink-lab uses from nlink today (0.15.1)

- `nlink::Connection<Route>` for link/address/route/qdisc
  management (most deploys).
- `nlink::Connection<Nftables>` for firewall + NAT (imperative
  `add_table` / `add_chain` / `add_rule`).
- `nlink::Connection<Wireguard>` for WireGuard tunnels.
- `nlink::netlink::impair::PerPeerImpairer` for per-pair
  HTB+netem+flower trees (the Plan 128 feature, the big
  differentiator versus containerlab).
- `nlink::netlink::ratelimit::RateLimiter` for per-endpoint
  ingress/egress shaping.
- `nlink::netlink::namespace::connection_for(...)` to
  open netns-bound connections.
- `nlink::netlink::link::{VethLink, BridgeLink, VlanLink,
  BondLink, VrfLink, VxlanLink, WireguardLink, DummyLink}`
  for veth/bridge/VLAN/bond/VRF/VXLAN/WG construction.
- `nlink::netlink::bridge_vlan::BridgeVlanBuilder`.
- `nlink::netlink::diagnostics::{Diagnostics, InterfaceDiag,
  Issue}` for `nlink-lab diagnose`.

### What changes after the 0.17 bump

- `apply_firewall` + `apply_nat` (currently ~300 LOC of
  imperative `add_*` calls) shrink to a single
  `NftablesConfig::diff().apply()` call per node.
- The `del_table` + rebuild reconcile path in
  `apply_nftables_diff` (`crates/nlink-lab/src/deploy.rs:2900-
  2947`) is deleted. Re-apply on an unchanged topology
  becomes zero kernel calls.
- Kernel error messages (`EPERM`, `EINVAL`) now carry
  `NLMSGERR_ATTR_MSG` detail strings inline via `Error::Kernel
  { ext_ack }` — surfaced for free in existing
  `format!("…: {e}")` error wrappers.

### nlink-lab's adoption plan files

If you want full context, the four sub-plans are committed
in the nlink-lab repo at:

```
docs/plans/158-nlink-0.16-0.17-adoption.md     (umbrella)
docs/plans/158a-nftables-reconcile.md          (P1, blocked on Ask 1)
docs/plans/158b-error-ext-ack.md               (P2)
docs/plans/158c-from-parse-error.md            (P3)
docs/plans/158d-watch-nft-events.md            (P3, optional, motivates Ask 2)
```

---

## Self-check before opening the PRs

Before pushing, run from the nlink workspace root:

```bash
cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p nlink --lib
# Then the root-gated piece:
sudo -E cargo test -p nlink --test integration -- nat_chain_chain_type
```

Ask 1's wire-roundtrip test is the strongest guard against
silently emitting the wrong `NFTA_CHAIN_TYPE` value — please
keep it even if the integration test feels redundant.

---

## Wishlist (not asks — read when planning future cycles)

Beyond the two specific asks above, here are six items that
would meaningfully improve the nlink-lab experience if they
ever fit a nlink cycle. None are blocking. They're ranked by
nlink-lab impact (1 = most useful), and I've spec'd each just
enough that you can scope it without further context. **Skip
anything that doesn't fit your direction** — these are
gardening, not requirements.

### Wishlist 1 — `impl Display for NftablesDiff` + `NetworkDiff`

**Why nlink-lab cares.** nlink-lab's `apply --dry-run` and
`apply --check --json` commands today render their own
human-readable diff via custom `Display` impls on the
nlink-lab side. After 158a lands, the canonical diff is
upstream's `NftablesDiff` — and we'd render the same shape
upstream renders. A built-in `Display` impl would deduplicate
that work everywhere, including in `nft --debug=mnl`-style
debugging.

**Current state.** `NftablesDiff` (`crates/nlink/src/netlink/
nftables/config/diff.rs:165-194`) and `NetworkDiff` (`crates/
nlink/src/netlink/config/diff.rs`) have `change_count()`
getters but no `Display`. Consumers either format the struct
manually or render `Debug` (verbose, not human-friendly).

**Proposed shape.**

```text
NftablesDiff (12 changes):
  + table  inet/filter
  + chain  inet/filter/input        hook=input policy=drop priority=filter
  + chain  inet/filter/forward      hook=forward policy=drop priority=filter
  + rule   inet/filter/input        nlink:ssh-allow       tcp dport 22 accept
  + rule   inet/filter/input        nlink:icmp-allow      meta l4proto 1 accept
  ~ rule   inet/filter/input        nlink:http-allow      tcp dport 80 → 8080 accept
  - rule   inet/filter/input        nlink:legacy-allow    handle=42
```

(`+` add, `~` replace, `-` delete). Suggested as plain
`Display` (one event per line) plus an "alternate"
`{:#}` form that includes the raw netlink attributes for
debugging.

**Effort.** ~80 LOC + a Display-round-trip test for each
shape. The data is already structured; this is a rendering
pass.

**Same shape would be useful on**: `NetworkDiff`,
`ReconcileReport`, and the per-resource `Vec<DeclaredRule>`
field types. Easy to mass-roll if you want a "Display all
the diff types" PR.

---

### Wishlist 2 — `Connection<Nftables>::subscribe_all_with_resync(snapshot_fn)`

**Why nlink-lab cares.** Plan 158d (nlink-lab watch via
nftables multicast) wires `events_with_resync(conn.events(),
|| snapshot_dump())` per namespace. The snapshot fn we
write is mechanical:

```rust
async fn snapshot_dump(ns: &str) -> Result<Vec<NftablesEvent>> {
    let conn = Connection::<Nftables>::new_in_namespace_by_name(ns)?;
    let tables = conn.list_tables().await?;
    let chains = conn.list_chains().await?;
    let flowtables = conn.list_flowtables().await?;
    let mut rules = Vec::new();
    for t in &tables {
        rules.extend(conn.list_rules(&t.name, t.family).await?);
    }
    // Synthesize NewTable/NewChain/NewRule/NewFlowtable events
    // for each, return as a single Vec.
    …
}
```

Every consumer of `events_with_resync` for nftables will
write substantially the same code. A built-in:

```rust
impl Connection<Nftables> {
    /// Subscribe to the nftables multicast group with
    /// automatic ENOBUFS recovery. On overflow, dumps
    /// current state via list_tables/chains/rules/flowtables,
    /// emits ResyncStart + Resynced(...) per item +
    /// ResyncEnd, and resumes live events. Returns a stream
    /// of `ResyncedEvent<NftablesEvent>`.
    pub fn subscribe_all_with_resync(&mut self) ->
        Result<impl Stream<Item = Result<ResyncedEvent<NftablesEvent>>>>;
}
```

…would let nlink-lab Plan 158d shrink from ~60 LOC of
per-namespace plumbing to ~5.

**Effort.** ~60 LOC + 2 unit tests + 1 root-gated integration
test (flood rules to force ENOBUFS, assert resync sequence).

**Could mirror this** on `Connection<Netfilter>` (conntrack)
and `Connection<Route>` (link/addr/route events) — same
pattern, same value to downstream consumers.

---

### Wishlist 3 — `nlink::Error::ext_ack() -> Option<&str>` accessor

**Why nlink-lab cares.** Plan 158b threads kernel
`NLMSGERR_ATTR_MSG` text into nlink-lab's `--json` error
envelopes. Today the only way to extract that string is
pattern-match the variant:

```rust
let ext_ack = match &err {
    nlink::Error::Kernel { ext_ack, .. }
    | nlink::Error::KernelWithContext { ext_ack, .. } => ext_ack.as_deref(),
    _ => None,
};
```

…repeated at every site that wants the structured text.
With both variants now `#[non_exhaustive]`, this also
requires a `_ =>` wildcard at every call site. A simple
inherent:

```rust
impl Error {
    /// Return the kernel's `NLMSGERR_ATTR_MSG` string if
    /// this is a kernel error that carries one.
    pub fn ext_ack(&self) -> Option<&str> {
        match self {
            Error::Kernel { ext_ack, .. }
            | Error::KernelWithContext { ext_ack, .. } => ext_ack.as_deref(),
            _ => None,
        }
    }

    /// Return the `NLMSGERR_ATTR_OFFS` offset, if known.
    pub fn ext_ack_offset(&self) -> Option<u32> {
        match self {
            Error::Kernel { ext_ack_offset, .. }
            | Error::KernelWithContext { ext_ack_offset, .. } => *ext_ack_offset,
            _ => None,
        }
    }
}
```

…would let consumers write `err.ext_ack().unwrap_or_default()`.
Matches the existing `errno() -> Option<i32>` /
`is_busy() -> bool` / `is_try_again() -> bool` accessor
pattern at `error.rs:474-576`.

**Effort.** ~10 LOC + 2 unit tests. Five minutes.

---

### Wishlist 4 — `nlink::namespace::for_each_namespace_async`

**Why nlink-lab cares.** nlink-lab routinely fan-outs work
across every node namespace in a lab: deploy step 16 spawns
processes per node; `nlink-lab status --scan` lists running
labs; Plan 158d's watch mode spawns a subscriber per node.
Today nlink-lab writes the same "spawn a thread per
namespace, enter via setns, do work, join" boilerplate
several times.

```rust
// Sketch — return ordering preserved across input.
pub async fn for_each_namespace_async<F, Fut, T>(
    namespaces: impl IntoIterator<Item = String>,
    work: F,
) -> Vec<Result<T>>
where
    F: Fn(String) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    // One thread per namespace; setns inside the thread;
    // current_thread tokio runtime per thread; collect
    // results in input order.
}
```

**Caveats.** This is a more opinionated helper than
nlink usually ships — it hard-codes the
"thread-per-namespace + current_thread tokio runtime"
pattern. Maybe lives in a separate `nlink::lab` companion
crate? Or exposed only under a feature flag? You'd know
best.

**Effort.** ~120 LOC + 3 integration tests. Medium ask.
Could absorb the existing per-protocol
`Connection::<P>::new_in_namespace*` boilerplate too.

---

### Wishlist 5 — `Ipv4Route::default_route()` / `Ipv6Route::default_route()` constructors

**Why nlink-lab cares.** Every default-route call site in
`deploy.rs` reads:

```rust
nlink::netlink::route::Ipv4Route::new("0.0.0.0", 0)
nlink::netlink::route::Ipv6Route::new("::", 0)
```

The `"0.0.0.0"` / `"::"` literal-strings-meaning-default-route
idiom is iproute2 muscle-memory and entirely fine — but
declarative call sites read better as:

```rust
Ipv4Route::default_route()
Ipv6Route::default_route()
```

(`default()` is unfortunately taken by `Default::default()`
trait — `default_route()` avoids the collision and is also
self-documenting.)

**Effort.** ~5 LOC + 2 unit tests. Trivial.

---

### Wishlist 6 — `NetworkConfig` per-object reconcile parity with `NftablesConfig`

**The big one.** If you ever go for a unified "everything is
declarative-and-reconcilable" story across nlink, this is the
direction.

**Why nlink-lab cares.** nlink-lab's deploy is a 18-step
imperative sequence: namespace, bridges, veths, addresses,
routes, sysctls, rules, etc. (`crates/nlink-lab/src/deploy.rs`,
~3000 LOC). The 0.16 `NetworkConfig` already exists with
declarative builders for `link` / `address` / `route` /
`qdisc` and a `diff()` (`config/diff.rs`). If `NetworkConfig`
gained the same per-object reconcile shape `NftablesConfig`
just got (in 0.16 with USERDATA-keyed identity + atomic
`apply`), nlink-lab could:

1. Stop running an imperative 18-step deploy.
2. Run a single
   `topology_to_network_config(node) → NetworkConfig
   → diff → apply` per node.
3. Have idempotent re-apply across links / addresses /
   routes / qdiscs / sysctls — the same nirvana 158a gives
   us for nftables.
4. Drop ~1500 LOC of per-resource diff code in nlink-lab's
   `diff.rs` and `deploy.rs::apply_*_diff` family.

**What's missing today** (best guess — I haven't audited as
deeply as for `NftablesConfig`):

- The `0.16` per-object reconcile is real for links
  (by `name`), routes (by `destination`), addresses (by
  `dev + addr`). Confirmed via the
  `crates/nlink/src/netlink/config/diff.rs:434` Plan 147
  §4.4 entry in the CHANGELOG ("`NetworkConfig::diff` now
  detects same-kind / different-params qdisc changes").
- The `apply` path's atomicity is **not** equivalent to
  nftables — RTNETLINK has no `BATCH_BEGIN/END` primitive.
  An "atomic" `NetworkConfig::apply` would have to be
  best-effort rollback-on-error, which is a different shape
  than nftables's kernel-enforced atomicity. Worth
  scoping carefully.
- Cross-resource ordering (create link before address before
  route) needs to be implicit in the apply order.
- USERDATA-equivalent identity isn't available for RTNETLINK
  — names and destinations have to do.

**Effort.** Probably a multi-cycle effort. Worth a design
doc before any code. The biggest unlock for nlink-lab by far,
but also the biggest ask. **Tagging as a direction, not a
PR.**

---

## Contact

If anything is unclear or the API direction (Option A vs B
for Ask 2; the test-file placement; the migration-guide
entry style) doesn't match your conventions, ping me
(nlink-lab maintainer) before merging. The blocker (Ask 1)
is what nlink-lab is most eager to unblock — the
nice-to-have (Ask 2) can come whenever. The wishlist is
purely informational — none of it is gating any nlink-lab
work.

---

## Quick summary for triage

| Section | Items | What to do |
|---------|-------|------------|
| **Asks** | 1 blocking (`chain_type`), 1 nice (`list_*_in`) | Schedule. Ask 1 is the highest priority. |
| **Wishlist** | 6 items, ranked | Read once; pick anything that fits a future cycle. |
| **False alarms** | `PerHostLimiter::reconcile` already exists | Ignore — nlink-lab will update its stale comment. |
