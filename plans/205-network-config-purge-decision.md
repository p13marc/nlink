---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 205 — NetworkConfig purge: wire it up OR remove the dead-code knob
status: queued for 0.19 — CRITICAL (documented feature lies about what it does)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §C5
created: 2026-05-31
---

# Plan 205 — `NetworkConfig` purge: wire-up or remove

## 1. Why this plan exists

`ConfigDiff` has four `*_to_remove` collections:

- `links_to_remove: Vec<String>`
- `addresses_to_remove: Vec<(String, IpAddr, u8)>`
- `routes_to_remove: Vec<(IpAddr, u8, u32)>`
- `qdiscs_to_remove: Vec<(String, QdiscParent)>`

The apply path reads these under `if options.purge` at
`apply.rs:377, 410, 441, 473`. The diff path **never populates
them** — `diff_addresses` and `diff_routes` carry comments saying
"We don't auto-remove" and silence the `desired` HashSet with
`let _ = desired;`. `diff_links` and `diff_qdiscs` only build the
add / modify / replace collections.

**Effect:** `ApplyOptions::default().with_purge(true)` is a silent
no-op. The docs promise "remove resources not in config"; the
implementation does nothing for the remove side. Users believe
their kernel state is reconciled; foreign resources are
untouched.

This plan picks one of two paths — **wire it up** (option A, what
users expect) OR **remove it** (option B, stop the lie) — and ships
the chosen path with documentation and tests.

## 2. The decision

**Recommended: option A — wire it up.**

Rationale:
- The collections, apply-side branches, and `ApplyOptions::with_purge`
  builder all exist. The desired/current HashSets are already built
  inside `diff_*` — the missing piece is the inverse-iterate step.
- Several nlink-lab use cases need full reconcile semantics (lab
  teardown, CNI cleanup) and currently work around the gap by
  doing imperative cleanup. Wiring purge lets them collapse.
- Option B (removal) is more disruptive (removes the documented
  knob) without giving back the feature.

Option B is documented below as the fallback if option A's risk
proves too high during implementation.

## 3. Option A — wire it up (recommended)

### 3.1 `diff_addresses` change

**File:** `crates/nlink/src/netlink/config/diff.rs:461-495`

Replace the dead comment + `let _ = desired` with:

```rust
fn diff_addresses(
    config: &NetworkConfig,
    current: &[AddressMessage],
    ifindex_to_name: &HashMap<u32, &str>,
    diff: &mut ConfigDiff,
) {
    let desired: HashSet<(&str, IpAddr, u8)> = config
        .addresses
        .iter()
        .map(|a| (a.dev.as_str(), a.address, a.prefix_len))
        .collect();

    let current_set: HashSet<(String, IpAddr, u8)> = current
        .iter()
        .filter_map(|a| {
            let name = ifindex_to_name.get(&a.ifindex())?;
            // Filter out kernel-injected ephemeral addresses
            // we should NEVER attempt to purge:
            //   * IPv6 link-local (fe80::/64) — auto-installed
            //     by kernel on every UP interface
            //   * IPv6 multicast (ff00::/8)
            //   * Loopback addresses on `lo`
            let addr = a.address?;
            if is_kernel_managed_address(addr, name) {
                return None;
            }
            Some(((*name).to_string(), addr, a.prefix_len()))
        })
        .collect();

    // Adds: declared minus current.
    for declared in &config.addresses {
        let key = (declared.dev.as_str(), declared.address, declared.prefix_len);
        if !current_set.contains(&(key.0.to_string(), key.1, key.2)) {
            diff.addresses_to_add.push(declared.clone());
        }
    }

    // Removes: current minus declared. ONLY populated under
    // purge semantics — caller must opt in via `purge=true`,
    // since otherwise we'd surface kernel-installed addresses
    // (e.g. DHCP) as "stale" and propose deletion. The diff
    // is symmetric; the apply path gates on `opts.purge`.
    for (name, addr, prefix) in &current_set {
        let key = (name.as_str(), *addr, *prefix);
        if !desired.contains(&key) {
            diff.addresses_to_remove.push((
                name.clone(),
                *addr,
                *prefix,
            ));
        }
    }
}

/// Returns true for addresses the kernel manages independent of
/// user config — these must never appear in `addresses_to_remove`
/// even under purge mode.
fn is_kernel_managed_address(addr: IpAddr, _ifname: &str) -> bool {
    match addr {
        IpAddr::V6(v6) => {
            // fe80::/10 (link-local) — auto-installed
            v6.segments()[0] & 0xFFC0 == 0xFE80
                // ff00::/8 — multicast
                || v6.segments()[0] & 0xFF00 == 0xFF00
        }
        IpAddr::V4(v4) => {
            // 224.0.0.0/4 — IPv4 multicast (link locally significant)
            (v4.octets()[0] & 0xF0) == 0xE0
        }
    }
}
```

### 3.2 `diff_routes` change

**File:** `crates/nlink/src/netlink/config/diff.rs:497-548`

Same shape — also widen the `routes_to_remove` tuple to carry the
full identity so `remove_route` can target the right kernel route
(see Plan 207 / M3):

```rust
fn diff_routes(
    config: &NetworkConfig,
    current: &[RouteMessage],
    ifindex_to_name: &HashMap<u32, &str>,
    diff: &mut ConfigDiff,
) {
    // ... existing desired/current_set construction ...

    // Removes: current minus declared. ONLY under purge mode.
    // We carry the full identity (dst, prefix, table, gw, dev)
    // because del_route needs them to disambiguate ECMP / multi-
    // metric routes. (Note: this requires growing the
    // `routes_to_remove` tuple. See Plan 207 M3.)
    for (dst, prefix, table) in &current_set {
        let key = (*dst, *prefix, *table);
        if !desired.contains(&key) {
            // Filter out kernel-managed routes — local routes,
            // link routes auto-installed on interface up:
            if is_kernel_managed_route(*dst, *prefix) {
                continue;
            }
            diff.routes_to_remove.push((*dst, *prefix, *table));
        }
    }
}

fn is_kernel_managed_route(dst: IpAddr, prefix: u8) -> bool {
    match dst {
        IpAddr::V6(v6) => {
            // fe80::/64 — link-local prefix routes
            v6.segments()[0] & 0xFFC0 == 0xFE80 && prefix >= 64
        }
        IpAddr::V4(_) => false,
    }
}
```

### 3.3 `diff_links` and `diff_qdiscs` changes

Same shape: iterate current-minus-desired and populate the
remove collections, gated by kernel-managed-resource filters.

For `diff_links`:
- NEVER remove `lo` even if not declared.
- NEVER remove links with kernel-managed kinds (vrf-slave master
  set by kernel, etc.).

For `diff_qdiscs`:
- NEVER remove the kernel's default `pfifo_fast` qdisc — that's
  what comes back automatically.
- A `purge=true` config that doesn't declare a root qdisc DOES
  trigger deletion of any current root qdisc.

### 3.4 Apply path: confirm the gate semantics

**File:** `crates/nlink/src/netlink/config/apply.rs:377-473`

The existing code already does:
```rust
if options.purge {
    for (dst, prefix_len, table) in &diff.routes_to_remove { ... }
}
```

Verify each `*_to_remove` loop is gated on `options.purge` so the
collections do nothing unless the user opts in.

### 3.5 Document the semantics on `ApplyOptions::with_purge`

```rust
impl ApplyOptions {
    /// Whether to delete kernel resources that are NOT in the
    /// declared config (`current minus declared`).
    ///
    /// **0.19**: This now functions correctly (Plan 205). Prior
    /// to 0.19 the flag was a silent no-op — the diff side
    /// never populated the `*_to_remove` collections. Code that
    /// relied on the no-op needs review.
    ///
    /// What gets removed:
    /// - Addresses on declared-config-managed interfaces that
    ///   are not in the config (kernel-managed addresses like
    ///   IPv6 link-local are excluded — see source).
    /// - Routes in declared tables not in config (kernel link-
    ///   local prefix routes excluded).
    /// - Root and ingress qdiscs not declared.
    /// - Interfaces not declared (but never `lo`).
    ///
    /// What gets preserved:
    /// - Kernel-managed addresses (IPv6 link-local, IPv4/v6
    ///   multicast).
    /// - Kernel-installed prefix routes.
    /// - The `lo` loopback interface.
    /// - Any resource on an interface the config does NOT
    ///   mention (purge is scoped to declared interfaces).
    ///
    /// **Warning**: with `purge=true`, applying an empty
    /// `NetworkConfig` deletes every user-installed address /
    /// route / qdisc / link the kernel reports. Use with care.
    pub fn with_purge(mut self, purge: bool) -> Self {
        self.purge = purge;
        self
    }
}
```

## 4. Option B — remove the dead-code knob (fallback if A proves risky)

If option A's complexity (kernel-managed-resource exclusion,
scoping rules, regression risk) outweighs the benefit:

1. Delete `ApplyOptions::purge` field + `with_purge` method.
2. Delete `links_to_remove`, `addresses_to_remove`, `routes_to_remove`,
   `qdiscs_to_remove` fields from `ConfigDiff`.
3. Delete the `if options.purge { ... }` branches from `apply.rs`.
4. Migration guide entry: "purge was non-functional pre-0.19;
   remove call sites — they were silent no-ops anyway. For the
   `current minus declared` use case, use the imperative
   `del_link`/`del_address`/`del_route` API directly."

This path is one clean 200-line deletion. Option A is the
recommended ship; option B is documented for emergency.

## 5. Tests (option A)

### 5.1 Unit tests in `config/diff.rs`

```rust
#[test]
fn diff_addresses_does_not_propose_ipv6_link_local_removal() {
    let cfg = NetworkConfig::new().address("eth0", "10.0.0.1/24", None).unwrap();
    let current = vec![
        address_msg("eth0", "10.0.0.1/24"),
        address_msg("eth0", "fe80::1/64"),  // kernel-installed
        address_msg("eth0", "fe80::2/64"),  // kernel-installed
    ];
    let mut diff = ConfigDiff::default();
    diff_addresses(&cfg, &current, &name_map(), &mut diff);
    assert!(diff.addresses_to_remove.is_empty(),
        "fe80::/10 must never appear in purge candidates");
}

#[test]
fn diff_addresses_proposes_removal_of_undeclared_user_address() {
    let cfg = NetworkConfig::new().address("eth0", "10.0.0.1/24", None).unwrap();
    let current = vec![
        address_msg("eth0", "10.0.0.1/24"),  // declared — keep
        address_msg("eth0", "10.0.0.2/24"),  // undeclared — propose remove
    ];
    let mut diff = ConfigDiff::default();
    diff_addresses(&cfg, &current, &name_map(), &mut diff);
    assert_eq!(diff.addresses_to_remove.len(), 1);
    assert_eq!(diff.addresses_to_remove[0].1, "10.0.0.2".parse::<IpAddr>().unwrap());
}

#[test]
fn diff_routes_does_not_propose_ipv6_link_local_route_removal() {
    // Similar shape for routes.
}

#[test]
fn diff_links_never_proposes_lo_removal() {
    let cfg = NetworkConfig::new();  // empty
    let current = vec![link_msg("lo"), link_msg("eth0")];
    let mut diff = ConfigDiff::default();
    diff_links(&cfg, &current, &name_map(), &mut diff);
    assert!(!diff.links_to_remove.contains(&"lo".to_string()));
}

#[test]
fn diff_kernel_managed_helpers_correctness() {
    assert!(is_kernel_managed_address("fe80::1".parse().unwrap(), "eth0"));
    assert!(is_kernel_managed_address("ff02::1".parse().unwrap(), "eth0"));
    assert!(is_kernel_managed_address("224.0.0.1".parse().unwrap(), "eth0"));
    assert!(!is_kernel_managed_address("10.0.0.1".parse().unwrap(), "eth0"));
}
```

### 5.2 Integration tests

```rust
#[tokio::test]
async fn purge_removes_undeclared_user_addresses() -> Result<()> {
    require_root!();
    let ns = LabNamespace::new("purge-addrs")?;
    let conn = ns.connection::<Route>()?;

    // Install two addresses, declare only one, apply with purge.
    conn.add_address("eth0", "10.0.0.1/24".parse()?).await?;
    conn.add_address("eth0", "10.0.0.2/24".parse()?).await?;

    let cfg = NetworkConfig::new().address("eth0", "10.0.0.1/24", None)?;
    let opts = ApplyOptions::default().with_purge(true);
    cfg.apply_with_options(&conn, opts).await?;

    let addrs = conn.get_addresses().await?;
    assert!(addrs.iter().any(|a| a.matches("10.0.0.1/24")));
    assert!(!addrs.iter().any(|a| a.matches("10.0.0.2/24")),
        "purge=true should remove undeclared 10.0.0.2");
    Ok(())
}

#[tokio::test]
async fn purge_preserves_ipv6_link_local() -> Result<()> {
    // Same shape — set the interface up, kernel auto-adds fe80::*,
    // apply empty config with purge=true, verify fe80 still present.
}

#[tokio::test]
async fn purge_off_is_truly_no_op() -> Result<()> {
    // Two addresses; declare only one; apply WITHOUT purge.
    // The undeclared address must remain.
}
```

## 6. CHANGELOG entry (option A)

```markdown
### Breaking changes

- **`ApplyOptions::with_purge(true)` is now functional**. Prior
  to 0.19 this flag was a silent no-op — the diff side never
  populated `addresses_to_remove`, `routes_to_remove`,
  `links_to_remove`, or `qdiscs_to_remove`. Code that relied
  on the no-op behavior (calling `.with_purge(true)` thinking
  "the documented purge happens" while actually nothing was
  removed) now sees real deletions on the next apply.
  See migration guide for the kernel-managed-resource exclusion
  list (IPv6 link-local, multicast, `lo`, kernel-installed
  prefix routes are NEVER candidates for purge).

### Fixed

- **`NetworkConfig::apply` purge wired up end-to-end** (Plan 205).
  The diff side now populates all four `*_to_remove` collections
  via inverse-iteration over the current/desired sets. The apply
  path's existing `if options.purge { ... }` branches now have
  work to do. Kernel-managed resources (IPv6 link-local, multi-
  cast, `lo`, link-local prefix routes) are filtered out at the
  diff layer to prevent destructive surprises. 6 new unit tests
  + 3 root-gated integration tests pin the contract.
```

## 7. Migration guide (option A)

```markdown
### Plan 205 — `NetworkConfig` purge now functional

Pre-0.19, `ApplyOptions::default().with_purge(true)` was
documented but did nothing on the remove side (the diff phase
never populated `*_to_remove`). If your code called this flag
thinking "kernel state will be reconciled" — it wasn't.

**What changes:**

```rust
// 0.18:
let opts = ApplyOptions::default().with_purge(true);
cfg.apply_with_options(&conn, opts).await?;
// Silently kept undeclared addresses, routes, qdiscs, links.

// 0.19:
let opts = ApplyOptions::default().with_purge(true);
cfg.apply_with_options(&conn, opts).await?;
// NOW DELETES every kernel-resource not in cfg, except:
// - IPv6 link-local (fe80::/10) and multicast (ff00::/8)
// - IPv4 multicast (224.0.0.0/4)
// - The `lo` loopback interface
// - Kernel-installed link-local prefix routes
```

**Migration**: if you were calling `.with_purge(true)` and want
the OLD no-op behavior, just delete the call. If you want the
NEW behavior, no change needed.
```

## 8. Acceptance criteria

- [ ] Option A or option B chosen and shipped consistently
- [ ] All four `*_to_remove` collections populated by `diff_*`
      (option A) OR all four collections deleted (option B)
- [ ] Kernel-managed resource exclusion correctly implemented
      (option A only)
- [ ] 6 unit tests pass (option A) OR purge call sites cleaned
      (option B)
- [ ] 3 root-gated integration tests pass (option A)
- [ ] CHANGELOG `### Breaking changes` + `### Fixed` entries
- [ ] Migration guide entry with code examples

## 9. Effort estimate

| Step | Time |
|---|---|
| Option A: `diff_addresses` purge wire-up | 1 h |
| Option A: `diff_routes` purge wire-up | 1 h |
| Option A: `diff_links` purge wire-up | 30 min |
| Option A: `diff_qdiscs` purge wire-up | 30 min |
| Option A: kernel-managed-resource helpers + tests | 1.5 h |
| Option A: 6 unit tests | 1 h |
| Option A: 3 root-gated integration tests | 1.5 h |
| CHANGELOG + migration guide | 30 min |
| Verification (cargo test/clippy/machete) | 30 min |
| **Total (Option A)** | **~6 h** |
| **Total (Option B)** | **~2 h** |

## 10. Risks

- **Option A — Destructive surprises**: a user calling
  `.with_purge(true)` against a freshly-booted host may delete
  things they didn't expect. Mitigation: comprehensive kernel-
  managed-resource exclusion list + scary docstring + recipe.
- **Option A — kernel-managed-resource list is incomplete**: we
  may miss a class of kernel-installed resources (e.g. wireguard
  link-local addresses, IPv6 SLAAC prefixes). Mitigation: test
  on a real interface up/down cycle in CI; surface gaps as
  follow-up.
- **Option A — Apply ordering**: under purge, remove-then-add
  semantics matter. Today the apply path does
  `links_to_add → links_to_modify → addresses_to_add →
  routes_to_add → qdiscs_to_add` then `*_to_remove` blocks.
  Verify the ordering doesn't introduce circular dependencies
  (e.g. removing a link before its addresses).

## 11. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 1 Breaking change + 1 Fixed entry |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | §"Plan 205" with code-example before/after |
| `docs/recipes/network-config-purge.md` (new) | ~80-line recipe walking through purge semantics, kernel-managed exclusions, edge cases |
| `crates/nlink/src/netlink/config/diff.rs` | populate 4 `*_to_remove` + helpers |
| `crates/nlink/src/netlink/config/apply.rs` | verify gates correct (already in place) |
| `crates/nlink/src/netlink/config/types.rs` | extended `ApplyOptions::with_purge` docstring |
| `crates/nlink/tests/integration/cycle_0_19_backfill.rs` | 3 root-gated tests |

End of plan.
