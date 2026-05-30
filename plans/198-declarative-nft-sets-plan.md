---
to: nlink maintainers
from: 0.19 second consolidation-pass + nftables-sets research agent (2026-05-30)
subject: declarative nftables sets + vmaps — `DeclaredTableBuilder::set(name, |s| ...)` with element diff + concat key support
status: queued for 0.19 — medium (closes the last declarative-nftables surface)
target version: 0.19.0
parent: extends Plan 157 (`NftablesConfig`)
source: nlink-lab `nlink-feedback.md` §14 (declarative nft sets — marked "no signal" but pulled in under 0.19 "everything in 0.19" directive)
created: 2026-05-30
---

# Plan 198 — Declarative nftables sets + verdict maps

## 1. Why this plan exists

`DeclaredTableBuilder` exposes `.chain(...)`, `.rule(...)`,
`.flowtable(...)` — but no `.set(...)`. The imperative
`Connection<Nftables>::add_set` exists; the declarative
integration is the gap.

nlink-lab flagged this as low priority for them in
`nlink-feedback.md` §14 (they don't use sets). Under the 0.19
"everything in 0.19" directive (2026-05-30), it's in scope —
sets are a real nftables surface used by every blocklist-
shaped firewall and "drop traffic from this list" rule, and
shipping the declarative path now closes the LAST gap in
nftables declarative coverage.

The research-agent audit (2026-05-30) on the nft(8) set
ecosystem concluded:

- 6 key types worth modeling: 4 already in `SetKeyType`
  (`Ipv4Addr`, `Ipv6Addr`, `EtherAddr`, `InetService`,
  `IfIndex`, `Mark`) + `InetProto` (new) + `Concat(Vec<_>)`
  (new) for concatenated keys used in real rulesets.
- Set vs map vs vmap: all use `NFT_MSG_NEWSET` distinguished
  by `NFTA_SET_FLAGS` bits (`NFT_SET_MAP`, `NFT_SET_OBJECT`,
  etc.). One Rust type with optional `data_type` covers all
  three.
- Element diff: pure symmetric difference, no
  mid-element-replace. Add + remove only. Same identity
  model as Plan 157b v2's USERDATA-keyed rules but simpler
  (element values are the identity).
- Interval sets need a `.interval()` flag set BEFORE
  `.element_range(...)`; runtime check + clean error.

## 2. The change

### 2.1 Extend `SetKeyType` with `InetProto` + `Concat`

```rust
// crates/nlink/src/netlink/nftables/types.rs (existing SetKeyType)

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SetKeyType {
    Ipv4Addr, Ipv6Addr, EtherAddr,
    InetService, IfIndex, Mark,
    InetProto,                          // NEW — single u8 protocol
    Concat(Vec<SetKeyType>),            // NEW — composite key
}
```

The `Concat` variant matches the kernel's concatenated-key
encoding (used in rules like `ip saddr . tcp dport`). The
wire format packs each component value end-to-end with
4-byte alignment between.

### 2.2 `DeclaredSet` + builder

```rust
// crates/nlink/src/netlink/nftables/config/types.rs (extend)

bitflags::bitflags! {
    pub struct SetFlags: u32 {
        const CONSTANT  = 0x02;        // NFT_SET_CONSTANT
        const INTERVAL  = 0x04;        // NFT_SET_INTERVAL
        const DYNAMIC   = 0x10;        // NFT_SET_DYNAMIC
        const TIMEOUT   = 0x80;        // NFT_SET_TIMEOUT
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DeclaredSet {
    pub name: String,
    pub key_type: SetKeyType,
    pub data_type: Option<SetDataType>,        // None=set, Some=map/vmap
    pub flags: SetFlags,
    pub timeout: Option<Duration>,
    pub gc_interval: Option<Duration>,
    pub elements: BTreeSet<SetElement>,        // sorted for stable diff
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetDataType {
    Verdict,                                   // vmap
    U32, U64,
    Mark, Counter, Quota,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SetElement {
    pub key: SetElementKey,
    pub data: Option<SetElementData>,          // Some for map/vmap, None for set
    pub timeout: Option<Duration>,
}
```

Builder shape:

```rust
impl DeclaredTableBuilder {
    pub fn set(
        self,
        name: impl Into<String>,
        build: impl FnOnce(DeclaredSetBuilder) -> DeclaredSetBuilder,
    ) -> Self { ... }
}

impl DeclaredSetBuilder {
    pub fn key_type(self, t: SetKeyType) -> Self;
    pub fn interval(self) -> Self;              // sets the flag
    pub fn timeout(self, d: Duration) -> Self;
    pub fn constant(self) -> Self;
    pub fn dynamic(self) -> Self;

    pub fn element(self, e: SetElement) -> Self;
    pub fn elements(self, es: impl IntoIterator<Item = SetElement>) -> Self;

    /// Add a range element. REQUIRES `.interval()` to be set;
    /// returns an error at `build()` time if not.
    pub fn element_range(self, r: SetElementRange) -> Self;

    pub fn map_to_verdict(self) -> Self;        // data_type = Verdict
    pub fn map_to(self, t: SetDataType) -> Self;
}
```

### 2.2b `FromIterator` for ergonomic batch construction (idiom-pass addition)

Real-world use case: a blocklist comes from a feed (file,
database, REST API) as a `Vec<IpAddr>`. Let consumers
collect directly into a `DeclaredSet`:

```rust
impl FromIterator<SetElement> for DeclaredSet { ... }

impl FromIterator<IpAddr> for DeclaredSet {
    /// Build a `Ipv{4,6}Addr`-typed set from an iterator of
    /// addresses. Auto-detects v4 vs v6 from the first
    /// element; mixed iterators panic at construction time
    /// (mixed-family sets are not modeled).
    fn from_iter<I: IntoIterator<Item = IpAddr>>(it: I) -> Self;
}
```

Lets:

```rust
let blocked: DeclaredSet = std::fs::read_to_string("blocklist.txt")?
    .lines()
    .map(|s| s.parse::<IpAddr>())
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .collect();
```

### 2.2c `SetElement::ipv4(addr)` ergonomic constructors (idiom-pass addition)

The research agent's API uses `SetElement::ipv4(addr)`,
`SetElement::ipv6(addr)`, etc. Each is a one-line const fn.
Add the full set:

```rust
impl SetElement {
    pub const fn ipv4(addr: Ipv4Addr) -> Self;
    pub const fn ipv6(addr: Ipv6Addr) -> Self;
    pub const fn ether(mac: [u8; 6]) -> Self;
    pub fn inet_service(port: u16) -> Self;
    pub fn inet_proto(proto: u8) -> Self;
    pub fn mark(mark: u32) -> Self;

    pub fn ipv4_range(net: Ipv4Net) -> Self;     // for interval sets
    pub fn ipv6_range(net: Ipv6Net) -> Self;
}
```

`From<Ipv4Addr> for SetElement` + symmetric impls so consumers
can `addr.into()` interchangeably.

### 2.3 Diff integration in `NftablesConfig`

```rust
// crates/nlink/src/netlink/nftables/config/diff.rs (extend)

#[non_exhaustive]
pub struct NftablesDiff {
    ...existing fields...
    pub sets_to_add: Vec<DeclaredSet>,
    pub sets_to_modify: Vec<(String, SetElementDelta)>,
    pub sets_to_remove: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SetElementDelta {
    pub elements_to_add: Vec<SetElement>,
    pub elements_to_remove: Vec<SetElement>,
}
```

`compute_diff` calls `list_sets_in(table, family)` (Plan 181)
to get kernel state, computes:
- New set declaration → `sets_to_add`
- Set removed → `sets_to_remove`
- Set exists, elements differ → `sets_to_modify` with
  `SetElementDelta` (symmetric difference of `BTreeSet`)

### 2.4 Transaction integration

`Transaction::add_set` + `Transaction::add_set_element` +
`Transaction::del_set_element` already exist imperatively;
the declarative `NftablesDiff::apply` orchestrates them in
the existing batch.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — `SetKeyType` extension (`InetProto`, `Concat`) | `nftables/types.rs` | ~50 |
| 2 — `DeclaredSet` + `DeclaredSetBuilder` | `config/types.rs` | ~120 |
| 3 — `SetFlags` bitflags + `SetDataType` enum | `types.rs` + `config/types.rs` | ~60 |
| 4 — `compute_diff` set-aware (BTreeSet symmetric diff) | `config/diff.rs` | ~80 |
| 5 — `NftablesDiff::apply` set integration | `config/apply.rs` | ~80 |
| 6 — `Display` for `SetElementDelta` row | `config/diff.rs` | ~30 |
| 7 — Re-exports | `lib.rs` | ~5 |
| 8 — Recipe + example | new files | ~200 |
| 9 — Tests (see §4) | various | ~350 |
| **Total** | | **~975 LOC** |

## 4. Tests

### 4.1 Unit — builder semantics

```rust
#[test]
fn set_builder_carries_all_knobs() {
    let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
        t.set("blocked_ips", |s| s
            .key_type(SetKeyType::Ipv4Addr)
            .interval()
            .element(SetElement::ipv4_range("10.0.0.0/8".parse().unwrap()).into())
            .timeout(Duration::from_secs(300)))
    });
    // Assert the set carries all fields.
}

#[test]
fn element_range_without_interval_flag_errors_at_build() {
    let result = std::panic::catch_unwind(|| {
        NftablesConfig::new().table("filter", Family::Inet, |t| {
            t.set("s", |s| s
                .key_type(SetKeyType::Ipv4Addr)
                // NO .interval() here
                .element_range(...))
        })
    });
    // Either panics at build or returns Error::InvalidMessage.
    // Pin the contract.
}

#[test]
fn vmap_builder_sets_data_type_verdict() {
    let cfg = ... .set("blocklist", |s| s
        .key_type(SetKeyType::Ipv4Addr)
        .map_to_verdict()
        .element(...));
    let set = cfg.tables().first().unwrap().sets().first().unwrap();
    assert_eq!(set.data_type, Some(SetDataType::Verdict));
}

#[test]
fn concat_key_round_trips() {
    let kt = SetKeyType::Concat(vec![
        SetKeyType::Ipv4Addr,
        SetKeyType::InetService,
    ]);
    // Validate that the encoder produces the right wire
    // format (key_len = 4 + 2 = 6 bytes with 4-byte aligned
    // padding).
}
```

### 4.2 Unit — element diff (the headline)

```rust
#[test]
fn diff_new_elements_become_add() {
    let cfg_set: BTreeSet<SetElement> = ["A", "B", "C"].into_iter().map(elem).collect();
    let kernel_set: BTreeSet<SetElement> = ["B", "C"].into_iter().map(elem).collect();
    let delta = compute_set_delta(&cfg_set, &kernel_set);
    assert_eq!(delta.elements_to_add, vec![elem("A")]);
    assert!(delta.elements_to_remove.is_empty());
}

#[test]
fn diff_stale_elements_become_remove() {
    let cfg_set: BTreeSet<SetElement> = ["A"].into_iter().map(elem).collect();
    let kernel_set: BTreeSet<SetElement> = ["A", "B"].into_iter().map(elem).collect();
    let delta = compute_set_delta(&cfg_set, &kernel_set);
    assert_eq!(delta.elements_to_remove, vec![elem("B")]);
}

#[test]
fn diff_identical_elements_is_noop() { ... }

#[test]
fn diff_full_symmetric_difference() {
    // cfg = {A, B, C}; kernel = {B, C, D}.
    // Expected: add A, remove D.
}
```

### 4.3 Wire-shape

```rust
#[test]
fn add_set_emits_nfta_set_flags_for_interval() {
    let set = DeclaredSet {
        flags: SetFlags::INTERVAL,
        ...
    };
    let bytes = build_add_set_request(&set);
    let flags_attr = find_attr(&bytes, NFTA_SET_FLAGS).unwrap();
    let value = u32::from_be_bytes(flags_attr.try_into().unwrap());
    assert!(value & 0x04 != 0);
}

#[test]
fn add_set_emits_concat_key_with_correct_bytes() {
    // Concat(Ipv4Addr, InetService) = 4 + 2 = 6 byte key.
    // Verify NFTA_SET_KEY_LEN attribute carries 6.
}

#[test]
fn add_set_vmap_emits_data_type_attribute() {
    // data_type = Verdict → NFTA_SET_DATA_TYPE = NFT_DATA_VERDICT.
}
```

### 4.4 Integration — root-gated round-trip

```rust
#[tokio::test]
async fn declarative_set_with_elements_round_trips() -> Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-set-decl")?;
    let nft = nft_in_ns(&ns)?;

    let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
        t.set("blocked_ips", |s| s
            .key_type(SetKeyType::Ipv4Addr)
            .element(SetElement::ipv4("1.2.3.4".parse().unwrap()).into())
            .element(SetElement::ipv4("5.6.7.8".parse().unwrap()).into()))
    });
    cfg.apply(&nft).await?;

    let sets = nft.list_sets_in("filter", Family::Inet).await?;
    let blocked = sets.iter().find(|s| s.name == "blocked_ips")
        .expect("set must exist after apply");
    assert_eq!(blocked.key_type, SetKeyType::Ipv4Addr);
    // Element count + members verified via get_set_elements (existing API).

    Ok(())
}

#[tokio::test]
async fn declarative_set_element_drift_repairs_via_reconcile() -> Result<()> {
    // 1. Apply config with {A, B, C}.
    // 2. From a different connection, add an out-of-band D.
    // 3. Re-apply. Verify D is removed via the delta.
}

#[tokio::test]
async fn declarative_vmap_drops_specific_source() -> Result<()> {
    // Vmap: source IP → verdict. Apply config that maps
    // 10.0.0.1 → drop. Verify rule references the vmap +
    // a packet from 10.0.0.1 is actually dropped (e.g. via
    // iptables-style traffic test using veth pair).
}
```

## 5. Acceptance criteria

- [ ] `SetKeyType` extended with `InetProto` + `Concat`.
- [ ] `DeclaredSet` + `DeclaredSetBuilder` + `SetFlags`
      bitflags + `SetDataType` enum.
- [ ] `compute_diff` handles sets (add, modify-via-delta,
      remove).
- [ ] `NftablesDiff::apply` orchestrates set ops in the
      existing batch.
- [ ] `.element_range()` errors when `INTERVAL` flag absent.
- [ ] 4+ unit tests (builders) + 4+ unit tests (diff) + 3+
      wire-shape tests + 3+ root-gated integration tests
      including drift-and-repair.
- [ ] Recipe + example.
- [ ] CHANGELOG entry.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~975 LOC) | ~5 h |
| Unit + wire-shape tests | ~2 h |
| Integration tests | ~2 h |
| Recipe + example | ~1.5 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~11 h** |

## 7. Risks

- **Concat key encoding edge cases**: components with
  irregular alignment (e.g. ether_addr is 6 bytes, not
  4-byte aligned) need padding. Wire-shape test pins the
  exact byte sequence.
- **Interval set ranges crossing boundaries**: the kernel
  allows `{10.0.0.0/8, 192.168.0.0/16}` as two non-
  overlapping intervals in one set. Diff must treat them as
  distinct elements; the BTreeSet comparison by range start
  + end suffices.
- **Vmap verdict types** (`drop`, `accept`, `goto chain`,
  etc.) — verify our `Verdict` enum covers what's needed +
  matches the kernel's `NFT_DATA_VERDICT` shape.

## 8. Out-of-scope follow-ups

- **Anonymous sets** (inline rule sets like
  `tcp dport { 22, 80, 443 }`): nftables supports these in
  rule expressions. They're a different shape — not named
  sets. Plan 157's rule builder could be extended later.

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Added` entry for declarative nftables sets + vmaps + concat keys | Cross-reference Plan 157 (declarative nftables) as the foundation. |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 198` section | Pure additive; no migration. |
| `docs/recipes/nftables-declarative-config.md` (exists) | **update** with a sets + vmaps section | The existing recipe covers tables/chains/rules; add sets. |
| `docs/recipes/nftables-blocklist.md` (**new**) | **create** ~140-line recipe walking a declarative IP blocklist with periodic updates from a feed | The canonical use case; closes the loop on "why I'd want declarative sets". |
| `docs/recipes/README.md` | **add row** for `nftables-blocklist.md` | One line. |
| `crates/nlink/examples/nftables/declarative_set.rs` (**new**) | **create** ~80-line demo | Register in `Cargo.toml`. |
| `README.md` `## High-Level APIs` "Declarative Network Configuration" sub-section | **update** to mention sets + vmaps in the nftables coverage | One-line update. |
| `CLAUDE.md` | **append** to the existing nftables section noting set + vmap declarative coverage is now complete | Closes the gap originally documented in Plan 157. |

End of plan.
