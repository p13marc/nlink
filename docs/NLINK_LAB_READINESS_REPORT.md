# nlink-lab Readiness Report

*Assessment of nlink library readiness for the nlink-lab network lab engine*

**Date:** 2026-03-22

---

## 1. Gap Status Summary

The NLINK_LAB.md document identified 5 gaps in the nlink library. After auditing the
current codebase, the actual status is:

| Gap | Severity | Status | Action Needed |
|-----|----------|--------|---------------|
| Gap 1: Sysctl Management | Critical | **NOT IMPLEMENTED** | Must add before lab work |
| Gap 2: Namespace Process Execution | Critical | **NOT IMPLEMENTED** | Must add before lab work |
| Gap 3: NetworkConfig Namespace Awareness | High | **NOT IMPLEMENTED** | Can defer — lab engine builds its own topology layer |
| Gap 4: VRF Table Assignment | Medium | **ALREADY WORKS** | No action needed |
| Gap 5: Interface Rename | Medium | **ALREADY IMPLEMENTED** | No action needed |

**Bottom line: 2 critical gaps remain, 1 high gap is deferrable, 2 gaps are already resolved.**

---

## 2. Detailed Gap Analysis

### Gap 1: Sysctl Management — MUST IMPLEMENT

**Current state:** Zero sysctl support. No `sysctl.rs` module, no methods on `Connection`,
no `/proc/sys/` file operations.

**What exists that helps:**
- `namespace::execute_in(name, closure)` — can execute arbitrary code inside a namespace
- `namespace::enter(name)` — returns `NamespaceGuard` for thread-level namespace switching

**What's needed:**
```rust
// Minimal API for nlink-lab
conn.set_sysctl("net.ipv4.ip_forward", "1").await?;
conn.get_sysctl("net.ipv4.ip_forward").await?;  // -> "1"
conn.set_sysctls(&[
    ("net.ipv4.ip_forward", "1"),
    ("net.ipv6.conf.all.forwarding", "1"),
]).await?;
```

**Implementation approach:** Read/write `/proc/sys/` files. For namespace-aware operation,
use `namespace::execute_in()` or open files after `setns()`. This is filesystem I/O, not
netlink — could be a standalone module or part of the namespace module.

**Estimated effort:** Small (1-2 days). The hard part (namespace switching) already exists.

**Blocking scenarios without this:**
- Routers can't forward packets (`net.ipv4.ip_forward=1`)
- MPLS label switching (`net.mpls.conf.<dev>.input=1`)
- SRv6 segment routing (`net.ipv6.conf.all.seg6_enabled=1`)
- ARP proxy, rp_filter tuning, etc.

---

### Gap 2: Namespace Process Execution — MUST IMPLEMENT

**Current state:** No public process spawning API. The test infrastructure uses
`ip netns exec` (shelling out to the `ip` command), which is not acceptable for a library.

**What exists:**
- `namespace::enter(name)` / `namespace::enter_path(path)` — thread-level `setns()` with guard
- `namespace::execute_in(name, closure)` — run a closure in a namespace
- `namespace::create()` / `delete()` / `list()` / `exists()`
- Full `NamespaceSpec` abstraction (Default, Named, Path, Pid variants)

**What's missing:** A way to spawn a child process that runs in a different network namespace.
`execute_in()` runs a closure in the *current thread* (via `setns`), which is fine for
filesystem operations but not for spawning long-lived processes.

**What's needed:**
```rust
// Spawn a process in a namespace
let child = namespace::spawn("myns", Command::new("iperf3").arg("-s"))?;

// Async variant
let handle = namespace::spawn_async("myns", cmd)?;
let output = handle.wait_with_output().await?;

// Or via connection
let child = conn.spawn(Command::new("nginx"))?;
```

**Implementation approach:** Two viable strategies:
1. **`fork()` + `setns()` + `exec()`** — standard Unix approach, works everywhere
2. **Pre-fork with `clone3(CLONE_NEWNET)`** — more elegant but Linux-specific
3. **Simpler: use `CommandExt::pre_exec()`** — Rust's `std::os::unix::process::CommandExt`
   lets you call `setns()` in the child process between `fork()` and `exec()`. This is the
   cleanest approach:

```rust
use std::os::unix::process::CommandExt;

pub fn spawn(ns_name: &str, mut cmd: Command) -> Result<Child> {
    let ns_fd = namespace::open(ns_name)?;
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(ns_fd.as_raw_fd(), libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(cmd.spawn()?)
}
```

**Estimated effort:** Small-medium (2-3 days). The `pre_exec` + `setns` pattern is
well-known. Main work is API design, error handling, and testing.

**Blocking scenarios without this:**
- Can't run iperf3, nginx, or any application inside lab nodes
- Can't run test workloads (the entire point of the lab tool)
- Test integration (section 7 of the design doc) is impossible

---

### Gap 3: NetworkConfig Namespace Awareness — DEFERRABLE

**Current state:** `NetworkConfig` operates on a single `Connection<Route>`, which maps
to a single namespace. No namespace field in any declared type. No multi-namespace support.

**Why it's deferrable:** The nlink-lab engine will build its own `TopologyConfig` abstraction
that orchestrates multiple `NetworkConfig` instances (one per namespace) or directly uses
the lower-level nlink APIs. The lab engine IS the multi-namespace orchestrator — it doesn't
need `NetworkConfig` to be namespace-aware internally.

**What the lab engine would do instead:**
```rust
for node in &topology.nodes {
    let conn = namespace::connection_for(&node.ns_name)?;
    // Use conn directly for per-namespace operations
    // Or create a NetworkConfig per namespace
    let config = NetworkConfig::new()
        .address("eth0", "10.0.0.1/24")?;
    config.apply(&conn).await?;
}
```

**Future enhancement:** If `NetworkConfig` gains namespace awareness later, the lab engine
can adopt it. But it's not a blocker for Phase 1.

**Estimated effort if done:** Medium (1 week). Would require rethinking the diff/apply
pipeline to handle multiple connections.

---

### Gap 4: VRF Table Assignment — ALREADY WORKS

**Current state:** Fully implemented and tested.

- `VrfLink::new("vrf-red", 100)` — creates VRF with routing table
- `conn.set_link_master("eth0", "vrf-red")` — enslaves interface to VRF
- Integration test at `crates/nlink/tests/integration/link.rs:240-266` verifies the full flow

**Only missing piece:** VRF is not exposed in the `NetworkConfig` declarative builder
(`DeclaredLinkType` doesn't have a `Vrf` variant). This is a minor addition if needed
for the lab tool's declarative config, but the low-level API works today.

---

### Gap 5: Interface Rename — ALREADY IMPLEMENTED

**Current state:** Fully implemented, tested, and exposed in the CLI.

- `conn.set_link_name("oldname", "newname")` — rename by name
- `conn.set_link_name_by_index(ifindex, "newname")` — rename by index (namespace-safe)
- Integration test at `crates/nlink/tests/integration/link.rs:290-308`
- Exposed in `bins/ip/` CLI as `ip link set <dev> name <newname>`
- **Constraint:** Interface must be down before renaming

---

## 3. Additional Capabilities Already Present

The following capabilities needed by nlink-lab are confirmed working:

| Capability | Status | Notes |
|-----------|--------|-------|
| Namespace create/delete/list | Working | `namespace::create()`, `delete()`, `list()` |
| Cross-namespace connections | Working | `namespace::connection_for(name)`, `connection_for_pid()` |
| Veth with peer in other NS | Working | `VethLink::peer_netns_fd()`, `peer_netns_pid()` |
| Move interface to NS | Working | `set_link_netns_fd()`, `set_link_netns_pid()` |
| Interface rename | Working | `set_link_name()`, `set_link_name_by_index()` |
| All link types | Working | veth, bridge, vlan, vxlan, macvlan, bond, vrf, dummy, etc. |
| Address management | Working | IPv4/IPv6, CRUD, namespace-safe `*_by_index` variants |
| Route management | Working | Static, policy rules, nexthop groups, MPLS, SRv6 |
| TC/netem impairment | Working | 19 qdisc types, typed builders, full netem config |
| nftables firewall | Working | Tables, chains, rules, sets, NAT, atomic transactions |
| Bridge VLAN filtering | Working | PVID, tagged/untagged, VLAN ranges, tunnel mapping |
| WireGuard | Working | Full GENL config: device, peers, keys |
| Batch operations | Working | `conn.batch()` for multiple ops in one syscall |
| Event monitoring | Working | Multi-namespace `StreamMap`, all rtnetlink groups |
| Diagnostics | Working | Scan, bottleneck detection, connectivity checks |
| Rate limiting | Working | `RateLimiter`, `PerHostLimiter` high-level APIs |
| Namespace watching | Working | inotify-based `NamespaceWatcher` (feature-gated) |
| Link statistics | Working | `StatsTracker`, `StatsSnapshot`, rate calculation |
| FDB management | Working | Query, add, replace, delete, flush |

---

## 4. Recommendations

### Before Starting nlink-lab (Phase 1 blockers)

1. **Implement sysctl support** (~1-2 days)
   - Add `netlink/sysctl.rs` module
   - Provide `get_sysctl()`, `set_sysctl()`, `set_sysctls()` functions
   - Make them namespace-aware via `execute_in()` or `setns()` + file I/O
   - Test with `net.ipv4.ip_forward` in a network namespace

2. **Implement namespace process spawning** (~2-3 days)
   - Add `namespace::spawn()` using `CommandExt::pre_exec()` + `setns()`
   - Add `namespace::spawn_async()` for tokio integration
   - Support stdout/stderr capture and background processes
   - Test by spawning a simple process (e.g., `sleep`) in a namespace

### Nice-to-Have Improvements (not blocking)

3. **Add VRF to NetworkConfig** (~0.5 day)
   - Add `DeclaredLinkType::Vrf { table: u32 }` variant
   - Wire it up in the diff/apply pipeline
   - Useful for the declarative config path but not strictly needed

4. **Add `set_link_nomaster()` method** (~0.5 day)
   - Remove interface from its master device (bridge, bond, VRF)
   - Needed for clean teardown of VRF/bridge topologies
   - Check if this already works by setting master to 0

5. **Consider `set_link_up_by_index()` convenience** (if missing)
   - The lab engine will frequently need to bring up interfaces by index
   - Verify all `set_link_*` methods have `*_by_index` variants

### Architecture Suggestion

For the lab engine itself, I recommend **NOT** extending `NetworkConfig` with namespace
awareness (Gap 3). Instead, the lab engine should be its own orchestration layer that:

1. Parses topology TOML into a graph data structure
2. Creates namespaces via `namespace::create()`
3. Creates veth pairs with `VethLink::peer_netns_fd()` for cross-namespace links
4. Opens per-namespace connections via `namespace::connection_for()`
5. Uses the existing nlink APIs directly for per-namespace configuration
6. Applies sysctls via the new sysctl module
7. Spawns processes via the new namespace spawn API

This keeps nlink focused as a netlink library and puts the multi-namespace orchestration
logic where it belongs — in the lab engine.

---

## 5. Effort Summary

| Task | Effort | Blocks Lab Work? |
|------|--------|------------------|
| Sysctl support | 1-2 days | Yes |
| Namespace process spawning | 2-3 days | Yes |
| VRF in NetworkConfig | 0.5 day | No |
| set_link_nomaster | 0.5 day | No |
| **Total blocking work** | **3-5 days** | |

The NLINK_LAB.md document estimated "~1 week" for nlink library gaps. With Gap 4 and
Gap 5 already resolved, the actual remaining work is **3-5 days** — the two critical
gaps (sysctl + process spawn).

---

## 6. Conclusion

nlink is in excellent shape for nlink-lab. The document's claim that "nlink already provides
90%+ of the networking primitives needed" is accurate — and with Gap 4 (VRF) and Gap 5
(rename) already implemented, it's closer to 95%.

The two remaining critical gaps (sysctl management and namespace process spawning) are
well-scoped, low-risk additions that leverage existing infrastructure (`namespace::execute_in`,
`namespace::open`, `setns()`). They should be implemented first, then lab engine development
can begin immediately.
