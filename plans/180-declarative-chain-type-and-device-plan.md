---
to: nlink maintainers
from: nlink-lab upstream-asks report (2026-05-27) + adjacent-gap audit
subject: `DeclaredChainBuilder::chain_type(ChainType)` + `Chain`/`DeclaredChain` `device(name)` for netdev hooks
status: queued for 0.18 — small bundled chain-attribute completeness pass
target version: 0.18.0
parent: (none — single-deliverable plan)
source: nlink-lab maintainer report `nlink-upstream-asks.md` §Ask 1 + adjacent-gap finding (netdev hook missing `NFTA_CHAIN_HOOK_DEVICE`)
created: 2026-05-27
---

# Plan 180 — declarative chain type + netdev device

## 1. Why this plan exists

Two parallel chain-attribute gaps that surface the same way: a
chain is declared, the apply succeeds, but the kernel either
rejects the next operation (NAT verdicts on a chain that
defaulted to `ChainType::Filter`) or silently builds an
incomplete hook (netdev base chain with no `device`).

The **`chain_type` gap** is blocking nlink-lab's adoption of
`NftablesConfig::diff().apply()` for NAT chains (Plan 158a in
their repo). Today the imperative `Chain::chain_type(ChainType)`
builder method exists at `nftables/types.rs:522`, but the
declarative path strips it: `DeclaredChain` (lines 216–221)
carries `name`/`hook`/`priority`/`policy` only, and `apply.rs`
(lines 100–112) reconstructs the runtime `Chain` from those
four fields, dropping the type.

The **`device` gap** isn't tracked by nlink-lab but is the same
shape: `Hook::Ingress` + `Family::Netdev` both exist in the
enum, but `NFTA_CHAIN_HOOK_DEVICE` is referenced nowhere in
`crates/nlink/src/netlink/nftables/`. Any caller that tries to
build `type filter hook ingress device eth0 priority -150`
silently emits an incomplete request that the kernel rejects
with `EOPNOTSUPP`. Bundling the fix into the same cycle costs
~3 extra LOC and prevents the same bug surfacing in 0.19 from
a different downstream report.

## 2. The change

### 2.1 `chain_type` on `Chain` (already present) and `DeclaredChain` (new)

```rust
// crates/nlink/src/netlink/nftables/config/types.rs (around line 216)
pub struct DeclaredChain {
    pub(crate) name: String,
    pub(crate) hook: Option<Hook>,
    pub(crate) priority: Option<Priority>,
    pub(crate) policy: Option<Policy>,
    pub(crate) chain_type: Option<ChainType>,  // NEW
    pub(crate) device: Option<String>,          // NEW (for netdev hooks)
}

impl DeclaredChain {
    pub fn chain_type(&self) -> Option<ChainType> { self.chain_type }
    pub fn device(&self) -> Option<&str> { self.device.as_deref() }
}

impl DeclaredChainBuilder {
    /// Set the chain type. `ChainType::Filter` is the kernel
    /// default for base chains; `ChainType::Nat` is **required**
    /// for `prerouting`/`postrouting` NAT chains (otherwise
    /// `masquerade`/`snat`/`dnat` verdicts refuse to load with
    /// `EOPNOTSUPP` and the apply rolls back).
    pub fn chain_type(mut self, ct: ChainType) -> Self {
        self.chain_type = Some(ct);
        self
    }

    /// Set the bound device for `Hook::Ingress` / `Hook::Egress`
    /// chains in `Family::Netdev`. **Required** for netdev base
    /// chains; ignored on other families.
    pub fn device(mut self, dev: impl Into<String>) -> Self {
        self.device = Some(dev.into());
        self
    }
}
```

### 2.2 `device` on imperative `Chain` (new field + builder)

```rust
// crates/nlink/src/netlink/nftables/types.rs (around line 479)
pub struct Chain {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) hook: Option<Hook>,
    pub(crate) priority: Option<Priority>,
    pub(crate) chain_type: Option<ChainType>,
    pub(crate) policy: Option<Policy>,
    pub(crate) device: Option<String>,  // NEW
}

impl Chain {
    pub fn device(mut self, dev: impl Into<String>) -> Self {
        self.device = Some(dev.into());
        self
    }
}
```

### 2.3 Wire serialization

`connection.rs` `add_chain` (currently lines ~261–289) writes
the chain's nested `NFTA_CHAIN_HOOK` group with
`NFTA_HOOK_HOOKNUM` + `NFTA_HOOK_PRIORITY`. Extend it:

```rust
// inside the NFTA_CHAIN_HOOK nest
builder.append_attr_u32_be(NFTA_HOOK_HOOKNUM, hook.to_u32());
builder.append_attr_u32_be(NFTA_HOOK_PRIORITY, priority);
if let Some(dev) = &chain.device {
    builder.append_attr_str(NFTA_HOOK_DEV, dev);
}
```

Add `NFTA_HOOK_DEV = 3` to the constants module (matches
kernel UAPI `include/uapi/linux/netfilter/nf_tables.h`).

### 2.4 Apply-path glue (declarative → imperative)

`crates/nlink/src/netlink/nftables/config/apply.rs:100-112`:

```rust
for (table_name, family, declared) in &self.chains_to_add {
    let mut chain = Chain::new(table_name, declared.name()).family(*family);
    if let Some(h) = declared.hook() { chain = chain.hook(h); }
    if let Some(p) = declared.priority() { chain = chain.priority(p); }
    if let Some(pol) = declared.policy() { chain = chain.policy(pol); }
    if let Some(ct) = declared.chain_type() { chain = chain.chain_type(ct); }
    if let Some(dev) = declared.device() { chain = chain.device(dev); }
    tx = tx.add_chain(chain);
}
```

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — wire `NFTA_HOOK_DEV` constant + add_chain serialization | `connection.rs` | ~10 |
| 2 — `Chain` field + builder | `types.rs` | ~10 |
| 3 — `DeclaredChain` fields + builder + getters | `config/types.rs` | ~30 |
| 4 — apply.rs glue | `config/apply.rs` | ~6 |
| 5 — `ChainInfo` parse (dump-side gains the same two fields) | `connection.rs` `parse_chain` | ~15 |
| **Total** | | **~70 LOC** |

The dump-side parse (phase 5) is the only piece nlink-lab's
report didn't call out — needed so the integration test can
read back the chain and assert `chain_type` round-trips.

## 4. Tests

### 4.1 Unit — declarative builder round-trip

```rust
#[test]
fn declared_chain_type_and_device_round_trip() {
    let cfg = NftablesConfig::new().table("ft", Family::Netdev, |t| {
        t.chain("ingress", |c| {
            c.hook(Hook::Ingress)
                .priority(Priority::new(-150))
                .chain_type(ChainType::Filter)
                .device("eth0")
        })
    });
    let chain = cfg.tables().first().unwrap().chains().first().unwrap();
    assert_eq!(chain.chain_type(), Some(ChainType::Filter));
    assert_eq!(chain.device(), Some("eth0"));
}
```

### 4.2 Unit — wire serialization

Mirror the existing `NFTA_CHAIN_POLICY` round-trip test
(search `add_chain_emits_*` in `connection.rs` tests). Build a
`Chain::new("t","c").chain_type(ChainType::Nat).device("eth0")`,
capture the transaction bytes via `Transaction::finish`, parse,
assert `NFTA_CHAIN_TYPE = "nat"` and `NFTA_HOOK_DEV = "eth0"`.

### 4.3 Integration (root-gated, two scenarios)

In `crates/nlink/tests/integration/nftables_reconcile.rs`:

```rust
#[tokio::test]
async fn nat_chain_chain_type_round_trips() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");
    // build NAT chain declaratively, apply, list_chains, assert
    // chain_type=Nat survives a kernel round-trip + masquerade
    // rule loads cleanly.
}

#[tokio::test]
async fn netdev_chain_device_round_trips() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables");
    // create a dummy eth0, declare netdev chain bound to it,
    // apply, list_chains, assert device="eth0" round-trips.
}
```

## 5. Acceptance criteria

- [ ] `DeclaredChainBuilder::chain_type(ChainType)` + `.device(name)`
      both compile and round-trip through `apply()`.
- [ ] `Chain::device(name)` builder on the imperative side.
- [ ] `NFTA_HOOK_DEV` written on `add_chain` when `device` set.
- [ ] `ChainInfo` exposes `chain_type: Option<ChainType>` +
      `device: Option<String>` populated by `parse_chain`.
- [ ] 2 unit tests + 2 integration tests, all green under root.
- [ ] CHANGELOG `### Added` entries for both surfaces; one-line
      note in `docs/migration_guide/0.17.0-to-0.18.0.md`.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~70 LOC across 4 files) | ~45 min |
| Unit tests (2) | ~30 min |
| Integration tests (2 — needs root env) | ~45 min |
| CHANGELOG + migration guide | ~15 min |
| **Total** | **~2.5 h** |

## 7. Risks

- **Netdev hook MULTI-DEVICE form (kernel 5.5+)**: the kernel
  also accepts a `NFTA_HOOK_DEVS` list-attribute for binding
  one chain to multiple devices. Out of scope for this plan
  (start with single-device `NFTA_HOOK_DEV`); if a consumer
  needs it, file a follow-up. The single-device form covers the
  common case.
- **Chain dump field stability**: `ChainInfo` is `#[non_exhaustive]`
  already (Plan 163), so adding the two fields is non-breaking.

## 8. Out-of-scope follow-ups

- **`flags` on `Chain`** — `NFTA_CHAIN_FLAGS` covers
  `NFT_CHAIN_BASE` (set implicitly by presence of hook) and
  `NFT_CHAIN_BINDING` (a more exotic case for set-element
  references). No downstream signal yet.
- **Multi-device netdev chains** — see Risks.

End of plan.
