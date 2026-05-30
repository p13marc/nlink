---
to: nlink maintainers
from: nlink-lab feedback `nlink-feedback.md` §1 + §2 (2026-05-30)
subject: VLAN parent ifindex resolution race — root-cause integration repro + fix; bundled `links_to_add` topo-sort
status: queued for 0.19 — HIGH (correctness); investigation-first
target version: 0.19.0
parent: (none — single-deliverable plan)
source: nlink-lab `nlink-feedback.md` §1 (HIGH) + §2 (medium)
created: 2026-05-30
---

# Plan 186 — VLAN parent resolution race + apply ordering

## 1. Why this plan exists

nlink-lab's 158e Slice 3 integration test
`slice3_vlan_iface_reapply_is_zero_ops` hit a reproducible failure
inside `NetworkConfig::apply`:

```
NetworkConfig::apply on 'host': interface not found: eth0
```

…on the second link create (a VLAN whose parent is the dummy
created immediately before, on the same `Connection<Route>`).
The kernel ACKed `add_link(Dummy("eth0"))`; the very next
`add_link(VlanLink("eth0.42", parent="eth0", 42))` resolved the
parent via `Connection::resolve_interface` → `get_link_by_name` →
`dump_typed(RTM_GETLINK)` and got `None` back.

The downstream report hypothesised two root causes:
**(a)** `Connection<Route>` caches dump results, or
**(b)** `resolve_interface` reads `/sys/class/net/` somewhere.

**Both are wrong** (audited at maintainer review):

- `Connection::resolve_interface`
  (`crates/nlink/src/netlink/connection.rs:1013`) calls
  `get_link_by_name`, which calls `dump_typed(RTM_GETLINK)` —
  a fresh netlink dump per call. No in-memory cache.
- `util::ifname::name_to_index` is the only sysfs reader in the
  crate, and it's only used by the `bins/` CLI helpers, never by
  library internals.
- `send_ack_inner` waits for an ACK frame with matching seq
  before returning. RTM_NEWLINK ACK = kernel committed the link.
  A subsequent dump on the same socket MUST see it (Linux
  RTNETLINK guarantee).

So the symptom is genuinely surprising. **The plan starts with a
diagnostic phase**: write an integration test that reproduces the
exact two-`add_link` sequence the maintainer ran, and see what
the test actually does. Only after we have a failing test do we
know what we're fixing.

## 2. Investigation phase (Phase 1 of the plan)

### 2.1 Repro integration test

In `crates/nlink/tests/integration/network_config_apply.rs` (new
file — currently no integration coverage for the apply path,
which is itself a gap):

```rust
//! Plan 186 §2.1 — repro the nlink-lab 158e Slice 3 symptom.
//! Creates a Dummy + VLAN sub-interface in the same
//! `NetworkConfig`, applies once, asserts both visible after.

use std::time::Duration;

use nlink::netlink::config::{NetworkConfig, ApplyOptions};
use nlink::netlink::{Connection, Route, namespace};
use crate::common::TestNamespace;

#[tokio::test]
async fn vlan_parent_dummy_in_same_apply_succeeds() -> nlink::Result<()> {
    nlink::require_root!();

    let ns = TestNamespace::new("vlan-parent-race")?;
    let conn = namespace::connection_for::<Route>(ns.name())?;

    let cfg = NetworkConfig::new()
        .link(|b| b.dummy("eth0"))
        .link(|b| b.vlan("eth0.42", "eth0", 42));

    // The downstream symptom: this returns
    // Err(InterfaceNotFound { name: "eth0" }) today.
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        cfg.apply(&conn),
    )
    .await
    .map_err(|_| nlink::Error::Timeout)??;

    assert_eq!(result.changes_made, 2);

    // Assert kernel-side visibility — both links must dump back.
    let links = conn.get_links().await?;
    assert!(
        links.iter().any(|l| l.name.as_deref() == Some("eth0")),
        "dummy 'eth0' must be in dump"
    );
    assert!(
        links.iter().any(|l| l.name.as_deref() == Some("eth0.42")),
        "vlan 'eth0.42' must be in dump"
    );

    Ok(())
}
```

### 2.2 Diagnosis branches

After running 2.1:

- **Green locally:** the symptom isn't reproducible in our test
  harness. Ship 2.1 as a regression test anyway and ask
  nlink-lab maintainer for the missing-piece details (kernel
  version, container vs host, connection-pool usage, exact
  config shape). Pause Phases 3-5 until we hear back.
- **Red locally:** add tracing/println to
  `send_ack_inner` + `send_dump_inner` to inspect:
  1. The seq number the ACK arrived with
  2. The frames inside the response buffer after the ACK is
     returned (are we discarding buffered frames that include
     the next dump's response?)
  3. The wall-clock between ACK return and next dump send
  4. The kernel's RTM_NEWLINK echo on multicast (Connection<Route>
     doesn't subscribe — but is it accidentally arriving anyway?)

Three speculative root causes worth pinging if red:
- **Buffer residue:** if the kernel bundled the
  `RTM_NEWLINK` echo (for a subscribed group we accidentally
  joined) into the same recvmsg as the ACK, and the recv-loop
  drops everything after returning Ok on the ACK, a subsequent
  same-socket read might miss data the kernel queued
  contiguously. (Unlikely — we don't subscribe by default.)
- **Strict-checking interaction:** if `enable_strict_checking`
  is on (Plan 155.2) the kernel may reject the GETLINK dump
  with a filter mismatch we're swallowing.
- **Kernel-version race:** `RTM_NEWLINK` ACK is committed but
  the rcu grace period for the dump iterator's snapshot lags.
  This would be a kernel bug; we'd have to retry-with-backoff
  defensively.

### 2.3 Reportable outcome

The investigation phase ships even if green: the new integration
test is a permanent guard against regression. INDEX.md notes
the resolution branch (green-and-asked vs red-and-fixed).

## 3. Fix shape — conditional on Phase 1 outcome

### 3a. If Phase 1 stays green ("not reproducible upstream")

Ship the integration test + the topo-sort below (§3c, valuable
on its own) + a docstring on `NetworkConfig::link`. Punt
deeper diagnostic on the report to nlink-lab.

### 3b. If Phase 1 goes red

Root-cause first; fix shape depends on what we find. Three
families of fix, in increasing invasiveness:

1. **Recv-loop discipline tweak** — if the buffer-residue
   hypothesis is right, the recv-loop in `send_ack_inner`
   needs to drain remaining bytes (or re-queue them) before
   returning. Per-Connection<P> single-flight discipline keeps
   this safe.
2. **Internal retry-with-backoff** — if the symptom is a
   kernel-side rcu race, `resolve_interface` retries the
   missing-name lookup once (after 1 ms) before failing.
   ~10 LOC, opt-out is unsound.
3. **Single-message GETLINK** — replace the
   `dump → filter` pattern in `get_link_by_name` with a
   targeted `RTM_GETLINK` carrying `IFLA_IFNAME` (kernel
   3.10+). The targeted form is coherent with prior ACKs in
   the same way; if it ALSO fails to see the new link, the
   bug is genuinely kernel-side.

We'd reach for (3) first regardless of which root cause turns
out to be it: it's a cleaner shape, ~30 LOC, more efficient
(no full dump for a name lookup), and removes a class of
race-with-other-mutators that the current dump-filter pattern
exhibits even outside the apply path. Combine with (2) only
if (3) doesn't fix it.

### 3c. Topo-sort `links_to_add` (Item #2 in the feedback — ships either way)

Independent of the root cause for #1, `apply_diff` iterates
`links_to_add` in *declared* order, which is non-deterministic
when the caller built the config from a `HashMap`. Add a
`compute_diff` step that reorders entries so parent-dependent
kinds (today: `Vlan { parent, .. }`; future: bridge slaves,
macvlan parents, vxlan underlay-dev) land after their parents
in the same `NetworkConfig`. ~40 LOC.

```rust
// crates/nlink/src/netlink/config/diff.rs (around the existing
// compute_diff body, after the Vec<DeclaredLink> is built)
fn topo_sort_for_apply(links: &mut Vec<DeclaredLink>) {
    use std::collections::HashSet;
    let mut placed = HashSet::new();
    let mut out = Vec::with_capacity(links.len());
    let mut remaining: Vec<DeclaredLink> = std::mem::take(links);

    // Repeat until everything is placed (or we detect a cycle —
    // shouldn't happen because the declared graph is by name
    // and `declared_parent_name` returns a single edge).
    let mut progress = true;
    while !remaining.is_empty() && progress {
        progress = false;
        let mut keep = Vec::with_capacity(remaining.len());
        for link in remaining.drain(..) {
            let parent = declared_parent_name(&link);
            let ready = parent.is_none_or(|p| placed.contains(p));
            if ready {
                placed.insert(link.name.clone());
                out.push(link);
                progress = true;
            } else {
                keep.push(link);
            }
        }
        remaining = keep;
    }
    // Anything left has an unsatisfied parent (declared parent
    // not in the config + not in the kernel — let apply fail
    // with the natural ENODEV/InterfaceNotFound rather than
    // silently dropping). Append them at the end.
    out.append(&mut remaining);
    *links = out;
}

fn declared_parent_name(link: &DeclaredLink) -> Option<&str> {
    match &link.link_type {
        DeclaredLinkType::Vlan { parent, .. }
        | DeclaredLinkType::Macvlan { parent, .. } => Some(parent),
        _ => None,
    }
}
```

The sort is stable for hash-defeating input pairs, which
matches nlink-lab's own
`network_config_vlan_parent_dummy_declared_first_regardless_of_hashmap_order`
unit test expectation.

## 4. Tests

### 4.1 Integration — repro (`crates/nlink/tests/integration/network_config_apply.rs` new file)

Already shown in §2.1. Add three more cases bundled into the
same file:

- `vlan_parent_dummy_in_same_apply_succeeds` (§2.1) — the
  headline.
- `vlan_parent_dummy_declared_in_either_order` — mirrors
  nlink-lab's hash-defeating test. Calls `cfg.apply()` with
  the dummy declared *after* the VLAN; topo-sort must
  reorder.
- `vlan_parent_already_exists_in_kernel` — pre-create the
  dummy by hand (the working path today), then declare only
  the VLAN. Verifies the topo-sort doesn't mis-handle
  external parents.
- `chain_of_three_dependent_links` — Dummy + VLAN(parent=Dummy)
  + Macvlan(parent=VLAN). Walks the topo-sort N-deep.

All four root-gated via `require_root!()`.

### 4.2 Unit — topo-sort

In `crates/nlink/src/netlink/config/diff.rs` tests:

```rust
#[test]
fn topo_sort_places_parent_before_child() {
    let mut links = vec![
        DeclaredLink { name: "vlan0".into(), link_type: vlan("dummy0", 42), .. },
        DeclaredLink { name: "dummy0".into(), link_type: Dummy, .. },
    ];
    topo_sort_for_apply(&mut links);
    assert_eq!(links[0].name, "dummy0");
    assert_eq!(links[1].name, "vlan0");
}

#[test]
fn topo_sort_handles_chain_of_three() {
    let mut links = vec![
        macvlan("mac0", parent: "vlan0"),
        vlan("vlan0", parent: "dummy0", 42),
        Dummy("dummy0"),
    ];
    topo_sort_for_apply(&mut links);
    assert_eq!(
        links.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(),
        vec!["dummy0", "vlan0", "mac0"]
    );
}

#[test]
fn topo_sort_preserves_independent_link_order() {
    // Two unrelated dummies must keep their declared order
    // (no spurious reordering for non-parent-dependent links).
    let mut links = vec![Dummy("a"), Dummy("b"), Dummy("c")];
    topo_sort_for_apply(&mut links);
    assert_eq!(
        links.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(),
        vec!["a", "b", "c"]
    );
}

#[test]
fn topo_sort_appends_unsatisfiable_parents_at_end() {
    // VLAN whose parent isn't declared + isn't in the kernel —
    // belongs at the end so apply fails with the natural
    // ENODEV at create time, not silently dropped.
    let mut links = vec![
        vlan("vlan0", parent: "missing", 42),
        Dummy("other"),
    ];
    topo_sort_for_apply(&mut links);
    assert_eq!(links.last().unwrap().name, "vlan0");
}
```

### 4.3 Unit / wire-shape — single-message GETLINK (only if §3b option 3 ships)

If we replace `get_link_by_name` with a targeted RTM_GETLINK
single-get carrying `IFLA_IFNAME`, add a wire-shape unit test
mirroring Plan 181's `build_list_*_request_*` shape:

```rust
#[test]
fn build_get_link_by_name_request_emits_ifla_ifname() {
    let bytes = build_get_link_by_name_request("eth0").finish();
    // Assert nlmsg_type=RTM_GETLINK, flags=NLM_F_REQUEST (NOT DUMP),
    // body carries ifinfomsg + IFLA_IFNAME="eth0\0"
    ...
}
```

## 5. Acceptance criteria

- [ ] New `crates/nlink/tests/integration/network_config_apply.rs`
      with four root-gated cases covering the dummy-then-VLAN,
      declared-out-of-order, parent-already-exists, and
      three-deep-chain scenarios.
- [ ] Phase 1 outcome documented in CHANGELOG (whether green
      stayed green or red caused the §3b fix).
- [ ] Topo-sort in `compute_diff` for parent-dependent link
      kinds + 4 unit tests covering placement, chain, no-op,
      unsatisfiable.
- [ ] `NetworkConfig::link` rustdoc paragraph about parent-
      child ordering (Item D1 in the feedback — bundled here
      because it's the same surface).
- [ ] (Conditional on §3b) recv-loop discipline or targeted
      RTM_GETLINK fix; matching wire-shape unit test.
- [ ] CHANGELOG `### Fixed` entry; migration guide entry in
      `0.18.0-to-0.19.0.md` (new file).

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Phase 1: repro integration test + run | ~1 h |
| Phase 1 diagnosis (conditional) | up to 1 day |
| Phase 2: topo-sort + 4 unit tests | ~2 h |
| Phase 3: docstring | ~15 min |
| Phase 4: targeted RTM_GETLINK (only if needed) | ~2 h |
| CHANGELOG + migration guide | ~30 min |
| **Total (green path)** | **~4 h** |
| **Total (red path)** | **~1.5 days** |

## 7. Risks

- **Investigation might bottom out at "kernel-side rcu race"**,
  which we can't fix from userspace. In that case ship the
  retry-with-backoff (§3b option 2) as a defensive measure +
  document the underlying cause + file a kernel-side bug
  upstream. Worst-case outcome.
- **Topo-sort could mis-order existing-passing tests if a
  declared parent exists in the kernel but a sibling depends
  on the *new* version's MTU**. Out of scope — the topo-sort
  only orders `links_to_add` against each other, not against
  `links_to_modify`. Document the limit.

## 8. Out-of-scope follow-ups

- **Cross-phase dependency ordering** (e.g. addresses depend on
  links): `apply_diff` already does phases in the right order
  (links → addresses → routes); no fix needed.
- **W1 (dump-cache invalidation hook)** in the feedback — moot
  if our analysis is right; revisit only if §3b option 3 fixes
  the symptom by changing the dump shape.

End of plan.
