# Plan 012: Declarative Network Configuration - Completion Report

## Status: COMPLETED

## Summary

Implemented a declarative network configuration API that allows users to specify desired network state and have nlink compute and apply the necessary changes. The implementation supports links, addresses, routes, and qdiscs with diff calculation, dry-run mode, and idempotent apply operations.

## Implementation Details

### Files Created

| File | Purpose | Lines |
|------|---------|-------|
| `crates/nlink/src/netlink/config/mod.rs` | Module entry point with NetworkConfig impl | 125 |
| `crates/nlink/src/netlink/config/types.rs` | Core types and builders | 909 |
| `crates/nlink/src/netlink/config/diff.rs` | State diff computation | 437 |
| `crates/nlink/src/netlink/config/apply.rs` | Apply logic with options | 748 |
| `crates/nlink/tests/integration/config.rs` | Integration tests | 377 |

**Total: 2,596 lines of code**

### Files Modified

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/mod.rs` | Added `pub mod config;` |
| `crates/nlink/tests/integration.rs` | Added config test module |
| `CLAUDE.md` | Added declarative config documentation and examples |

### Core API

#### NetworkConfig Builder

```rust
use nlink::netlink::config::NetworkConfig;

let config = NetworkConfig::new()
    .link("br0", |l| l.bridge().up())
    .link("veth0", |l| l.veth("veth1").master("br0"))
    .address("br0", "192.168.1.1/24")?
    .route("10.0.0.0/8", |r| r.via("192.168.1.254"))?
    .qdisc("eth0", |q| q.netem().delay_ms(100));
```

#### Diff Computation

```rust
let diff = config.diff(&conn).await?;
println!("Links to add: {:?}", diff.links_to_add);
println!("Addresses to remove: {:?}", diff.addresses_to_remove);
```

#### Apply with Options

```rust
// Standard apply
let result = config.apply(&conn).await?;

// Dry-run mode
let result = config.apply_with_options(&conn, ApplyOptions {
    dry_run: true,
    continue_on_error: false,
    purge: false,
}).await?;

// Human-readable summary
for line in result.summary() {
    println!("{}", line);
}
```

### Supported Resource Types

#### Links

| Type | Builder Method |
|------|----------------|
| Dummy | `.dummy()` |
| Veth | `.veth("peer")` |
| Bridge | `.bridge()` |
| VLAN | `.vlan("parent", id)` |
| VXLAN | `.vxlan(vni)` |
| Macvlan | `.macvlan("parent")` |
| Bond | `.bond()` |

Link options: `.mtu(u32)`, `.master("bridge")`, `.up()`, `.down()`

#### Addresses

Supports both IPv4 and IPv6 with CIDR notation:
- `"192.168.1.1/24"`
- `"2001:db8::1/64"`

#### Routes

| Type | Example |
|------|---------|
| Via gateway | `.route("10.0.0.0/8", \|r\| r.via("192.168.1.1"))` |
| Via interface | `.route("10.0.0.0/8", \|r\| r.dev("eth0"))` |
| Default | `.route("default", \|r\| r.via("192.168.1.1"))` |
| Blackhole | `.route("10.0.0.0/8", \|r\| r.blackhole())` |
| Unreachable | `.route("10.0.0.0/8", \|r\| r.unreachable())` |
| Prohibit | `.route("10.0.0.0/8", \|r\| r.prohibit())` |

#### Qdiscs

| Type | Builder | Parameters |
|------|---------|------------|
| Netem | `.netem()` | delay_ms, jitter_ms, loss_percent, duplicate_percent, reorder_percent |
| HTB | `.htb()` | default_class |
| FQ_Codel | `.fq_codel()` | target_us, interval_us, limit, flows, quantum |
| TBF | `.tbf()` | rate, burst |
| Prio | `.prio()` | bands |
| SFQ | `.sfq()` | perturb |

### ConfigDiff Structure

```rust
pub struct ConfigDiff {
    pub links_to_add: Vec<DeclaredLink>,
    pub links_to_remove: Vec<String>,
    pub links_to_modify: Vec<(String, LinkChanges)>,
    pub addresses_to_add: Vec<DeclaredAddress>,
    pub addresses_to_remove: Vec<DeclaredAddress>,
    pub routes_to_add: Vec<DeclaredRoute>,
    pub routes_to_remove: Vec<DeclaredRoute>,
    pub qdiscs_to_add: Vec<DeclaredQdisc>,
    pub qdiscs_to_remove: Vec<DeclaredQdisc>,
    pub qdiscs_to_replace: Vec<DeclaredQdisc>,
}
```

### Apply Ordering

The apply logic follows proper ordering to avoid dependency issues:

1. **Remove** qdiscs (clean up TC first)
2. **Remove** routes (before removing addresses)
3. **Remove** addresses (before removing links)
4. **Remove** links (last, as they may be dependencies)
5. **Add** links (first, as they are dependencies)
6. **Modify** links (MTU, master, state)
7. **Add** addresses (after links exist)
8. **Add** routes (after addresses exist)
9. **Add/Replace** qdiscs (last)

### Error Handling

- `AddressParseError` for invalid address strings
- `RouteParseError` for invalid route destinations
- `ApplyError` with resource type, name, operation, and underlying error
- `continue_on_error` option to collect all errors vs fail-fast

### Test Coverage

**11 tests** covering:
- Builder API (unit tests, no root required)
- Address parsing (IPv4 and IPv6)
- Route parsing (CIDR and default)
- Qdisc builder options
- Diff computation (links, addresses, routes)
- Apply operations (requires root)
- Idempotency verification
- Dry-run mode

## Design Decisions

### 1. Fluent Builder Pattern

Chose method chaining for ergonomic API:
```rust
NetworkConfig::new()
    .link("br0", |l| l.bridge().up())
    .address("br0", "10.0.0.1/24")?
```

### 2. Closure-based Configuration

Link, route, and qdisc builders use closures for nested configuration:
```rust
.link("eth0", |l| l.veth("eth1").mtu(9000))
```

### 3. String-based Address/Route Parsing

Addresses and routes parse from strings for convenience:
```rust
.address("eth0", "192.168.1.1/24")?  // Returns Result
.route("default", |r| r.via("192.168.1.1"))?
```

### 4. Qdisc Replacement Strategy

Qdiscs with the same device and parent are replaced rather than modified, as most qdisc parameters cannot be changed in-place.

### 5. No YAML/TOML Support (Yet)

Deferred serialization support to keep the initial implementation focused. Can be added later with serde derives.

## Verification

```bash
# Build passes
cargo build -p nlink

# Clippy passes (library code)
cargo clippy -p nlink -- -D warnings

# Unit tests pass
cargo test -p nlink

# Integration tests pass (with root)
sudo ./target/debug/deps/integration-* config --test-threads=1
```

## Branch

`feature/plan-012-declarative-config`

## Commits

```
feat(config): add declarative network configuration module
```

## Future Enhancements

1. **YAML/TOML Support**: Add serde derives for file-based configuration
2. **Rules Support**: Add routing rules to the declarative config
3. **TC Classes**: Support hierarchical class configuration
4. **Validation**: Pre-apply validation for configuration consistency
5. **Watch Mode**: Continuously reconcile state with desired config
6. **Namespace Support**: Apply config to specific network namespaces
