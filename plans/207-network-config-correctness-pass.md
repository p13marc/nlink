---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 207 — NetworkConfig correctness pass (H2, H3, H4, M3, M4, M5, M10, M18, M19)
status: queued for 0.19 — HIGH (multiple silent reconcile-divergence bugs)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §H2, H3, H4, M3, M4, M5, M10, M18, M19
created: 2026-05-31
---

# Plan 207 — `NetworkConfig` correctness pass

## 1. Why this plan exists

The second audit found six distinct silent-reconcile-divergence
bugs in `NetworkConfig` and three smaller ergonomic / idempotency
bugs. They all live in `config/diff.rs` and `config/apply.rs`. This
plan bundles them as one correctness pass.

| Finding | Bug |
|---|---|
| **H2** | Link `master` change undetected (`Option<String>` vs `Option<u32>` comparison) |
| **H3** | Route identity ignores gateway/dev/metric — silent no-op on common ops |
| **H4** | `apply_reconcile` retries non-atomic apply → masks original error with EEXIST |
| **M3** | `remove_route` drops `table`/`metric`/`dev` — routes in non-default tables can't be purged |
| **M4** | Address diff prefix-length identity wrong → prefix-change becomes EEXIST |
| **M5** | Topo-sort misses VXLAN underlay / Macvlan / master deps |
| **M10** | `LinkState::Down` declared on no-carrier admin-up interface silently no-ops |
| **M18** | `replace_qdisc` is non-atomic (del + add window) |
| **M19** | Flowtable diff identity is name-only (devs/priority changes silently no-op) |

All of these touch the diff layer. Several require widening the
`ConfigDiff` structure (breaking) — within the user's "OK to break
backward compat" authorization.

## 2. The changes

### 2.1 H2 — Resolve master ifindex → name for comparison

**File:** `crates/nlink/src/netlink/config/diff.rs:425-459`
(`compute_link_changes`).

Add `name_by_ifindex` arg to the function and resolve
`existing.master` (`Option<u32>`) to a name. Then compare
strings.

```rust
fn compute_link_changes(
    declared: &DeclaredLink,
    existing: &LinkMessage,
    name_by_ifindex: &HashMap<u32, String>,   // NEW
) -> LinkChanges {
    let mut changes = LinkChanges::default();

    // ... existing field comparisons ...

    // Resolve existing master ifindex → name for comparison.
    let existing_master_name: Option<&str> = existing
        .master_ifindex()
        .and_then(|idx| name_by_ifindex.get(&idx).map(|s| s.as_str()));

    match (&declared.master, existing_master_name) {
        (Some(want), Some(have)) if want == have => {} // unchanged
        (Some(want), Some(_have)) => {
            // master changes (e.g. br1 → br0)
            changes.set_master = Some(want.clone());
        }
        (Some(want), None) => {
            changes.set_master = Some(want.clone());
        }
        (None, Some(_)) => {
            changes.unset_master = true;
        }
        (None, None) => {}
    }

    changes
}
```

The caller (`diff_links`) needs to build `name_by_ifindex` once
and pass it through.

### 2.2 H3 — Widen route identity

**File:** `crates/nlink/src/netlink/config/diff.rs:497-548`

Change `ConfigDiff::routes_to_add` semantics from "only adds, never
modifies" to "always RTM_NEWROUTE with NLM_F_REPLACE" (replace-or-
create). Drop the misleading identity tuple at the diff layer; the
apply path becomes idempotent on its own.

Alternative (more invasive but correct): introduce
`routes_to_modify` and widen identity to `(dst, prefix, table,
gateway, dev_ifindex, metric)`. This is the path the master plan
authorizes.

```rust
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct ConfigDiff {
    // ... existing fields ...

    /// Routes whose `(dst, prefix, table)` exists in the kernel
    /// but at least one of `gateway`/`dev`/`metric` differs from
    /// the declared form. Pre-0.19 these silently no-op'd.
    pub routes_to_modify: Vec<DeclaredRoute>,
}
```

Identity becomes `(dst, prefix, table)`. When the key is in both
sets, compare the rest of the fields and queue
`routes_to_modify` if anything differs. Apply uses
`NLM_F_REPLACE` for these.

### 2.3 H4 — `apply_reconcile` recomputes diff per iteration

**File:** `crates/nlink/src/netlink/config/mod.rs:154-172`

Replace:
```rust
loop {
    match self.apply(conn).await {
        Ok(result) => { /* success */ }
        Err(e) if (e.is_busy() || e.is_try_again()) && attempt < opts.max_retries => {
            // retry whole apply ...
        }
        Err(e) => return Err(e),
    }
}
```

With:
```rust
loop {
    // Recompute diff at the start of each retry. After a
    // partial apply, the kernel state has changed; the next
    // attempt should target what's still missing, not re-run
    // the full original apply. This avoids the previously-
    // observed EEXIST masking the original EBUSY.
    let diff = self.diff(conn).await?;
    if diff.is_empty() {
        return Ok(ReconcileReport::no_op());
    }

    match diff.apply(conn, ApplyOptions::default()).await {
        Ok(result) => return Ok(ReconcileReport::success(attempt, result)),
        Err(e) if (e.is_busy() || e.is_try_again()) && attempt < opts.max_retries => {
            attempt += 1;
            tokio::time::sleep(opts.backoff_for(attempt)).await;
            continue;
        }
        Err(e) => return Err(e),
    }
}
```

Document this in the `apply_reconcile` rustdoc: each retry sees
fresh kernel state, so partial-progress + retry produces correct
behavior. Caveat: callers concerned about wall-clock budget
should set `max_retries` accordingly (Plan 207 adds optional
`max_duration` too if budget allows).

### 2.4 M3 — `remove_route` accepts full route key

**File:** `crates/nlink/src/netlink/config/apply.rs:821-837`

Plus `routes_to_remove` widening in diff.rs to carry full identity.

```rust
async fn remove_route(
    conn: &Connection<Route>,
    dst: IpAddr,
    prefix_len: u8,
    table: u32,
    gateway: Option<IpAddr>,
    dev: Option<u32>,            // ifindex
    metric: Option<u32>,
) -> Result<()> {
    let mut config = match dst {
        IpAddr::V4(v4) => Ipv4Route::from_addr(v4, prefix_len),
        IpAddr::V6(v6) => Ipv6Route::from_addr(v6, prefix_len),
    };
    if table != 254 {
        config = config.table(table);
    }
    if let Some(gw) = gateway {
        config = config.gateway(gw);
    }
    if let Some(dev) = dev {
        config = config.oif(dev);
    }
    if let Some(m) = metric {
        config = config.metric(m);
    }
    conn.del_route(config).await
}
```

Diff side widens `routes_to_remove` to `Vec<RemoveRouteSpec>` (a
struct carrying the full identity; this avoids unwieldy tuple
growth).

### 2.5 M4 — Address diff identity is `(dev, addr)`

**File:** `crates/nlink/src/netlink/config/diff.rs:467-490`

Change identity from `(dev, addr, prefix_len)` to `(dev, addr)`,
storing prefix as data. When prefix differs, queue replace (use
`NLM_F_REPLACE` on the kernel call).

```rust
let desired: HashSet<(&str, IpAddr)> = config
    .addresses
    .iter()
    .map(|a| (a.dev.as_str(), a.address))
    .collect();

// Plus a HashMap<(dev, addr), prefix> for comparing the data side.
let desired_prefix: HashMap<(&str, IpAddr), u8> = config
    .addresses
    .iter()
    .map(|a| ((a.dev.as_str(), a.address), a.prefix_len))
    .collect();

// On key match but prefix differ → modify (replace).
```

### 2.6 M5 — Topo-sort knows VXLAN underlay + master deps

**File:** `crates/nlink/src/netlink/config/diff.rs:367-423`

Extend `parent_of` to return all deps (vec, not option):

```rust
fn deps_of(link: &DeclaredLink, names_in_batch: &HashSet<&str>) -> Vec<String> {
    let mut deps = Vec::new();
    match &link.link_type {
        DeclaredLinkType::Vlan { parent, .. } => deps.push(parent.clone()),
        DeclaredLinkType::Macvlan { parent, .. } => deps.push(parent.clone()),
        DeclaredLinkType::Vxlan { underlay_dev: Some(dev), .. } => {
            deps.push(dev.clone());
        }
        _ => {}
    }
    // Master is a separate field on the link itself.
    if let Some(master) = &link.master {
        deps.push(master.clone());
    }
    deps.retain(|d| names_in_batch.contains(d.as_str()));
    deps
}
```

Then run Kahn's algorithm with the multi-dep edges.

### 2.7 M10 — `LinkState::Down` uses IFF_UP flag, not OperState

**File:** `crates/nlink/src/netlink/config/diff.rs:428-441`

```rust
match declared.state {
    LinkState::Up => {
        if existing.flags & IFF_UP == 0 {
            changes.set_up = true;
        }
    }
    LinkState::Down => {
        if existing.flags & IFF_UP != 0 {
            changes.set_down = true;
        }
    }
    LinkState::Unchanged => {}
}
```

Optional: surface `OperState` as a separate field for diagnostics,
but the diff input remains the admin flag.

### 2.8 M18 — `replace_qdisc` uses atomic RTM_NEWQDISC with NLM_F_REPLACE

**File:** `crates/nlink/src/netlink/config/apply.rs:921-937`

The TC subsystem supports `NLM_F_REPLACE` on `RTM_NEWQDISC` for
atomic replace. Use it instead of del-then-add.

```rust
async fn replace_qdisc(conn: &Connection<Route>, qdisc: &DeclaredQdisc) -> Result<()> {
    // Use NLM_F_REPLACE on RTM_NEWQDISC for atomic replace.
    // Eliminates the transient pfifo_fast window.
    add_qdisc_with_flags(conn, qdisc, NLM_F_REPLACE).await
}
```

If the lib doesn't expose a flag-taking variant, add one.

### 2.9 M19 — Flowtable diff compares devs/priority/flags

**File:** `crates/nlink/src/netlink/nftables/config/diff.rs:612-634`

Change identity from name-only to `(name, frozenset(devs),
priority, flags)`. Or symmetric-diff like the rest of the module:
remove + add when any field differs.

```rust
for f in declared.flowtables() {
    match current_by_name.get(f.name()) {
        None => diff.flowtables_to_add.push(f.clone()),
        Some(current) => {
            if !flowtables_match(current, f) {
                diff.flowtables_to_replace.push(f.clone());
            }
        }
    }
}
```

## 3. Tests

### 3.1 Unit (in `config/diff.rs` test mod)

```rust
#[test]
fn master_change_from_br1_to_br0_emits_set_master() {
    // declared: dummy0.master("br0"); kernel: dummy0.master(ifindex of br1)
    let mut name_by_ifindex = HashMap::new();
    name_by_ifindex.insert(5, "br1".to_string());
    name_by_ifindex.insert(7, "br0".to_string());
    let existing = link_msg_with_master("dummy0", 5);  // ifindex of br1
    let declared = declared_link("dummy0", Some("br0"));
    let changes = compute_link_changes(&declared, &existing, &name_by_ifindex);
    assert_eq!(changes.set_master.as_deref(), Some("br0"));
}

#[test]
fn route_gateway_change_appears_in_routes_to_modify() {
    let cfg = NetworkConfig::new()
        .route("10.0.0.0/8", |r| r.via("192.0.2.99"))?;
    let kernel_routes = vec![route_msg("10.0.0.0/8", "192.0.2.1", None, None)];
    let mut diff = ConfigDiff::default();
    diff_routes(&cfg, &kernel_routes, &name_map(), &mut diff);
    assert_eq!(diff.routes_to_modify.len(), 1);
    assert!(diff.routes_to_add.is_empty());
}

#[test]
fn address_prefix_change_creates_modify_not_add() {
    // kernel: 10.0.0.1/24 on eth0
    // declared: 10.0.0.1/16 on eth0
    let cfg = NetworkConfig::new()
        .address("eth0", "10.0.0.1/16", None)?;
    let kernel = vec![addr_msg("eth0", "10.0.0.1/24")];
    let mut diff = ConfigDiff::default();
    diff_addresses(&cfg, &kernel, &name_map(), &mut diff);
    // No additions; one modify.
    assert!(diff.addresses_to_add.is_empty());
    // (We don't add `addresses_to_modify` in this plan unless
    //  we go the full route. The simpler alternative is to use
    //  NLM_F_REPLACE on the add path; verify whichever ships.)
}

#[test]
fn linkstate_down_works_on_no_carrier_admin_up() {
    let declared = declared_link("dummy0", None).down();
    let kernel = link_msg_with_flags("dummy0", IFF_UP);  // admin-up, no carrier
    let changes = compute_link_changes(&declared, &kernel, &HashMap::new());
    assert!(changes.set_down);
    assert!(!changes.set_up);
}

#[test]
fn toposort_orders_vxlan_after_underlay() {
    let cfg = NetworkConfig::new()
        .link("vxlan42", |l| l.vxlan(42).vxlan_underlay_dev("eth0"))
        .link("eth0", |l| l.dummy());
    let mut diff = ConfigDiff::default();
    diff_links_topo(&cfg, &[], &HashMap::new(), &mut diff);
    let positions: HashMap<String, usize> = diff
        .links_to_add
        .iter()
        .enumerate()
        .map(|(i, l)| (l.name.clone(), i))
        .collect();
    assert!(positions["eth0"] < positions["vxlan42"]);
}

#[test]
fn toposort_orders_slave_after_master() {
    let cfg = NetworkConfig::new()
        .link("dummy0", |l| l.dummy().master("br0"))
        .link("br0", |l| l.bridge());
    let mut diff = ConfigDiff::default();
    diff_links_topo(&cfg, &[], &HashMap::new(), &mut diff);
    let positions: HashMap<String, usize> = diff
        .links_to_add
        .iter()
        .enumerate()
        .map(|(i, l)| (l.name.clone(), i))
        .collect();
    assert!(positions["br0"] < positions["dummy0"]);
}
```

### 3.2 Integration (root-gated)

```rust
#[tokio::test]
async fn master_change_actually_moves_dummy_between_bridges() -> Result<()> {
    require_root!();
    let ns = LabNamespace::new("master-move")?;
    let conn = ns.connection::<Route>()?;

    NetworkConfig::new()
        .link("br0", |l| l.bridge())
        .link("br1", |l| l.bridge())
        .link("dummy0", |l| l.dummy().master("br0"))
        .apply(&conn).await?;

    // Now change to br1.
    NetworkConfig::new()
        .link("br0", |l| l.bridge())
        .link("br1", |l| l.bridge())
        .link("dummy0", |l| l.dummy().master("br1"))
        .apply(&conn).await?;

    let link = conn.get_link_by_name("dummy0").await?;
    let br1 = conn.get_link_by_name("br1").await?;
    assert_eq!(link.master_ifindex(), Some(br1.ifindex()));
    Ok(())
}

#[tokio::test]
async fn route_gateway_change_propagates_to_kernel() -> Result<()> {
    require_root!();
    // Install 10.0.0.0/8 via gw1, then apply config with via gw2.
    // Verify kernel reports the new gateway.
}

#[tokio::test]
async fn apply_reconcile_recovers_after_partial_ebusy() -> Result<()> {
    require_root!();
    // Race: declare a link + an address on it. Force the
    // address-add to fail with EBUSY on first try by holding
    // a kernel lock briefly. The reconcile must succeed when
    // EBUSY clears, with the original error not masked.
}
```

## 4. CHANGELOG entry

```markdown
### Breaking changes

- **`ConfigDiff` grows `routes_to_modify`** and the
  `routes_to_remove` field changes from `Vec<(IpAddr, u8, u32)>`
  to `Vec<RemoveRouteSpec>` carrying the full route identity
  (gateway/dev/metric). Required to detect H3 and properly
  purge non-default-table routes (M3). `#[non_exhaustive]` was
  already in place from Plan 163; struct-literal construction
  of `ConfigDiff` was never supported.

- **`LinkChanges::set_master` semantics**: previously only fired
  when transitioning from `None` to `Some`. Now fires on any
  change (None→Some, Some→Some-different, Some→None via
  `unset_master`). Diff consumers reading `set_master` may
  observe more change events.

### Fixed

- **Link `master` change no longer silently no-ops** (H2). The
  comparison was structurally wrong — `Option<String>` (declared
  name) vs `Option<u32>` (kernel ifindex) treated as equal
  whenever both were `Some`. Now resolves ifindex via the
  diff's name map.

- **Route gateway/dev/metric changes no longer silently no-op**
  (H3). Diff now queues a `routes_to_modify` entry when key
  matches but data differs; apply uses `NLM_F_REPLACE`.

- **`NetworkConfig::apply_reconcile` recomputes the diff per
  retry** (H4). Pre-0.19, retrying re-ran the same apply against
  changed kernel state, producing EEXIST that masked the
  original EBUSY. Now each retry computes a fresh diff against
  current state.

- **`remove_route` carries full identity** (M3) — route table,
  gateway, dev, metric all forwarded so non-default-table
  purges work and ECMP routes are correctly disambiguated.

- **Address prefix-length change handled correctly** (M4) —
  previously `(dev, addr, /24)` → `(dev, addr, /16)` produced
  a new add tuple that the kernel rejected with EEXIST (kernel
  identity is `(dev, addr)`). Now uses `NLM_F_REPLACE`.

- **Topo-sort handles VXLAN underlay + master deps** (M5).
  Previously only Vlan and Macvlan parent deps were modeled;
  declaring `vxlan42.underlay_dev("eth0")` before `eth0` in
  the same batch reproduced the original Plan 186 bug.

- **`LinkState::Down` works on no-carrier admin-up interfaces**
  (M10). The comparison now reads `IFF_UP` from
  `ifi_flags`, not `IFLA_OPERSTATE`. Dummy/veth interfaces with
  no carrier (which is most of them in test namespaces)
  correctly observe the `down` request.

- **`replace_qdisc` is atomic** (M18) — uses `NLM_F_REPLACE` on
  `RTM_NEWQDISC` instead of del-then-add. Eliminates the
  transient `pfifo_fast` window.

- **Flowtable diff detects device/priority/flag changes** (M19)
  — previously name-only identity caused silent no-ops on
  mutation.
```

## 5. Migration guide

§"Plan 207" with code snippets showing:
- Old `routes_to_remove` tuple deconstruction → new struct field access.
- Old `set_master` semantics ("only None→Some") → new ("any change").
- Old reconcile error EEXIST → new clean EBUSY.

## 6. Acceptance criteria

- [ ] H2 — master change comparison resolves ifindex → name
- [ ] H3 — `routes_to_modify` collection populated; apply uses REPLACE
- [ ] H4 — `apply_reconcile` recomputes diff per iteration
- [ ] M3 — `remove_route` accepts full identity tuple
- [ ] M4 — Address diff identity is `(dev, addr)`, prefix is data
- [ ] M5 — Topo-sort handles vxlan_underlay + master deps
- [ ] M10 — `LinkState` comparison uses IFF_UP, not OperState
- [ ] M18 — `replace_qdisc` uses NLM_F_REPLACE
- [ ] M19 — Flowtable diff compares devs/priority/flags
- [ ] 6 unit tests pass
- [ ] 3 root-gated integration tests pass
- [ ] CHANGELOG entries
- [ ] Migration guide entry

## 7. Effort estimate

| Item | Time |
|---|---|
| H2 master change | 1 h |
| H3 route identity widening | 2 h |
| H4 reconcile diff-recompute | 1 h |
| M3 remove_route full identity | 1 h |
| M4 address prefix handling | 1 h |
| M5 topo-sort dep extension | 1 h |
| M10 IFF_UP read | 30 min |
| M18 NLM_F_REPLACE atomic | 30 min |
| M19 flowtable compare | 30 min |
| Tests (6 unit + 3 integration) | 2 h |
| CHANGELOG + migration guide | 30 min |
| **Total** | **~10 h** |

## 8. Risks

- **API surface grows**. `routes_to_modify`, `RemoveRouteSpec`
  struct, more `LinkChanges` field variants. `#[non_exhaustive]`
  hygiene from Plan 163 absorbs this, but doc updates needed.
- **NLM_F_REPLACE semantics differ subtly across kernels** for
  qdiscs (some kernels reject if the qdisc kind differs;
  some accept). Verify on representative kernel versions.
- **Reconcile recompute may surface edge cases** — what if the
  diff is empty after one retry but the original error indicated
  something else was wrong? Add a `tracing::warn!` for the
  unexpected-empty-diff case.

## 9. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 2 breaking + 9 fixed entries |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | §"Plan 207" |
| `crates/nlink/src/netlink/config/diff.rs` | main change site |
| `crates/nlink/src/netlink/config/apply.rs` | remove_route + replace_qdisc + reconcile |
| `crates/nlink/src/netlink/config/types.rs` | `RemoveRouteSpec`, `ConfigDiff` field grow |
| `crates/nlink/src/netlink/nftables/config/diff.rs` | M19 flowtable compare |
| `crates/nlink/tests/integration/cycle_0_19_backfill.rs` | 3 root-gated tests |
| `docs/recipes/network-config-purge.md` (new from Plan 205) | mention new behavior |

End of plan.
