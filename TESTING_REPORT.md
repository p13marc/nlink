# Testing Report: rip vs iproute2

## Executive Summary

The `rip` project currently has **53 unit tests** covering library crates but lacks integration/functional tests for the binary commands. In contrast, `iproute2` uses shell-based functional tests that run commands in isolated network namespaces. This report analyzes both approaches and recommends a testing strategy for `rip`.

---

## 1. iproute2 Testing Approach

### 1.1 Test Structure

```
iproute2/testsuite/
├── Makefile              # Test runner with namespace isolation
├── lib/
│   └── generic.sh        # Helper functions for tests
├── tests/
│   ├── ip/
│   │   ├── link/         # ip link tests
│   │   ├── route/        # ip route tests
│   │   ├── neigh/        # ip neighbor tests
│   │   ├── netns/        # ip netns tests
│   │   ├── rule/         # ip rule tests
│   │   └── tunnel/       # ip tunnel tests
│   ├── tc/               # tc command tests
│   ├── bridge/           # bridge command tests
│   └── ss/               # ss command tests
└── tools/
    └── generate_nlmsg.c  # Generates netlink message blobs for replay tests
```

### 1.2 Key Design Patterns

#### Network Namespace Isolation
```makefile
PREFIX := sudo -E unshare -n
```
Tests run in isolated network namespaces via `unshare -n`, providing:
- Clean network state for each test
- No interference with host networking
- Repeatable test environment
- No need for physical hardware

#### Shell-Based Functional Tests
Tests are shell scripts (`.t` files) that execute commands and verify output:
```bash
#!/bin/sh
. lib/generic.sh

NEW_DEV="$(rand_dev)"
ts_ip "$0" "Add $NEW_DEV dummy interface" link add dev $NEW_DEV type dummy
ts_ip "$0" "Show $NEW_DEV dummy interface" link show dev $NEW_DEV
test_on "$NEW_DEV"
test_lines_count 2
ts_ip "$0" "Del $NEW_DEV dummy interface" link del dev $NEW_DEV
```

#### Helper Functions (`lib/generic.sh`)
| Function | Purpose |
|----------|---------|
| `ts_ip`, `ts_tc`, `ts_bridge` | Execute commands with error capture |
| `ts_err` | Log test failure |
| `ts_skip` | Skip test (exit 127) |
| `test_on "pattern"` | Assert output contains pattern (regex) |
| `test_on_not "pattern"` | Assert output does NOT contain pattern |
| `test_lines_count N` | Assert output has N lines |
| `rand_dev` | Generate random device name |

#### Netlink Message Replay
For edge cases, iproute2 generates raw netlink message blobs:
```c
// tools/generate_nlmsg.c - creates binary netlink messages
int fill_vf_rate_test(void *buf, size_t buflen) {
    // Build a LinkMessage with specific VF attributes
    // Write to tests/ip/link/dev_wo_vf_rate.nl
}
```
Tests then replay these with `ip monitor file <blob>` to test parsing.

### 1.3 Test Coverage Areas

| Area | Tests | Focus |
|------|-------|-------|
| `ip link` | 4 | Create/delete virtual devices (dummy, bareudp, xfrm) |
| `ip route` | 1 | Add/show default routes (v4 and v6) |
| `ip neigh` | 1 | Basic neighbor operations |
| `ip netns` | 2 | Namespace ID operations, batch mode |
| `ip rule` | 1 | DSCP field handling |
| `ip tunnel` | 1 | Tunnel creation |
| `tc` | 5 | Batch mode, filters (flower, mpls, vlan), pedit actions |
| `bridge` | 2 | VLAN show, tunnel show |
| `ss` | 1 | Socket filters |

---

## 2. Current rip Test Coverage

### 2.1 Test Statistics

| Crate | Unit Tests | Lines of Code | Coverage Focus |
|-------|------------|---------------|----------------|
| `rip-netlink` | 30 | 8,587 | Message building, parsing, builders |
| `rip-lib` | 15 | 1,245 | Parsing utilities, address handling |
| `rip-output` | 4 | 769 | JSON/text formatting |
| `rip-tc` | 4 | 542 | Handle parsing |
| `bins/ip` | 0 | 4,107 | *No tests* |
| `bins/tc` | 0 | 2,823 | *No tests* |
| **Total** | **53** | **~22,000** | |

### 2.2 What's Tested (Unit Tests)

#### rip-netlink (30 tests)
- **Message parsing**: `parse_u32_ne`, `parse_cstring`, `parse_ipv4`, `nla_align`
- **Message building**: `test_simple_message`, `test_attribute`, `test_nested_attribute`
- **Message types**: Roundtrip tests for AddressMessage, LinkMessage, RouteMessage, etc.
- **TC options parsing**: `fq_codel_defaults`, `prio_defaults`
- **TC configuration builders**: `netem_builder`, `fq_codel_builder`, `tbf_builder`
- **Statistics**: Delta calculations, rate computations
- **Events**: Builder pattern verification

#### rip-lib (15 tests)
- **Parsing**: `get_u32`, `get_rate`, `get_size`, `get_time`
- **Addresses**: `parse_addr`, `parse_prefix`, `parse_mac`, `format_mac`
- **Device lookup**: `get_ifindex_lo`, `get_ifindex_not_found`
- **Interface names**: `validate`, `list_interfaces`

#### rip-output (4 tests)
- **Formatting**: `format_bytes`, `format_rate`, `format_duration`
- **JSON builder**: Basic JSON output

#### rip-tc (4 tests)
- **Handle operations**: `make_and_split`, `parse_handle`, `format_handle`

### 2.3 What's NOT Tested

| Gap | Impact |
|-----|--------|
| Binary commands (`ip`, `tc`) | No verification of CLI argument parsing |
| End-to-end operations | No verification of actual network changes |
| Error handling paths | Many error conditions untested |
| Edge cases in parsing | Complex command combinations |
| Output formatting | JSON/text output for various message types |
| Concurrent operations | No async/threading tests |

---

## 3. Recommended Testing Strategy

### 3.1 Three-Tier Testing Approach

```
┌─────────────────────────────────────────────────────────────┐
│  Tier 3: Functional Tests (shell scripts in namespaces)    │
│  - Full command execution                                   │
│  - Output verification                                      │
│  - Error message checking                                   │
├─────────────────────────────────────────────────────────────┤
│  Tier 2: Integration Tests (Rust, require root/netns)      │
│  - Connection to netlink                                    │
│  - Create/query/delete operations                           │
│  - Message roundtrips with kernel                           │
├─────────────────────────────────────────────────────────────┤
│  Tier 1: Unit Tests (Rust, no privileges)                  │
│  - Message serialization/deserialization                    │
│  - Parsing utilities                                        │
│  - Builder patterns                                         │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Tier 1: Expand Unit Tests (No Privileges Required)

**Priority: HIGH** - Can run in CI without special setup.

#### Add Message Roundtrip Tests
```rust
#[test]
fn test_link_message_serialize_deserialize() {
    let msg = LinkMessage::builder()
        .ifindex(5)
        .name("eth0")
        .mtu(1500)
        .flags(IFF_UP | IFF_RUNNING)
        .build();
    
    let bytes = msg.to_bytes();
    let parsed = LinkMessage::parse(&bytes).unwrap();
    
    assert_eq!(msg.ifindex(), parsed.ifindex());
    assert_eq!(msg.name, parsed.name);
    assert_eq!(msg.mtu, parsed.mtu);
}
```

#### Add CLI Argument Parsing Tests
```rust
// bins/ip/src/commands/link.rs
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    
    #[test]
    fn test_link_set_up() {
        let args = LinkCmd::try_parse_from(["link", "set", "eth0", "up"]).unwrap();
        // Verify parsed args
    }
    
    #[test]
    fn test_link_add_vlan() {
        let args = LinkCmd::try_parse_from([
            "link", "add", "vlan10", "link", "eth0", "type", "vlan", "id", "10"
        ]).unwrap();
        // Verify parsed args
    }
}
```

#### Add Netlink Message Blob Tests (like iproute2's generate_nlmsg)
```rust
// crates/rip-netlink/src/messages/fixtures.rs
const LINK_MESSAGE_WITH_STATS: &[u8] = include_bytes!("fixtures/link_with_stats.bin");

#[test]
fn test_parse_link_with_stats() {
    let msg = LinkMessage::parse(LINK_MESSAGE_WITH_STATS).unwrap();
    assert_eq!(msg.name.as_deref(), Some("eth0"));
    assert!(msg.stats.is_some());
}
```

### 3.3 Tier 2: Integration Tests (Require Privileges)

**Priority: MEDIUM** - Run with `cargo test --features integration`.

```rust
// crates/rip-netlink/tests/integration.rs
#![cfg(feature = "integration")]

use rip_netlink::{Connection, Protocol};

/// Run in network namespace: `sudo unshare -n cargo test --features integration`
#[tokio::test]
async fn test_create_dummy_interface() {
    let conn = Connection::new(Protocol::Route).unwrap();
    
    // Create dummy interface
    conn.create_link("test0", "dummy").await.unwrap();
    
    // Verify it exists
    let links = conn.get_links().await.unwrap();
    assert!(links.iter().any(|l| l.name.as_deref() == Some("test0")));
    
    // Clean up
    conn.delete_link("test0").await.unwrap();
}

#[tokio::test]
async fn test_add_netem_qdisc() {
    let conn = Connection::new(Protocol::Route).unwrap();
    
    // Create dummy interface
    conn.create_link("test0", "dummy").await.unwrap();
    conn.set_link_up("test0").await.unwrap();
    
    // Add netem qdisc
    let config = NetemConfig::new()
        .delay(Duration::from_millis(100))
        .loss(1.0)
        .build();
    conn.add_qdisc("test0", config).await.unwrap();
    
    // Verify qdisc exists
    let qdiscs = conn.get_qdiscs().await.unwrap();
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem"));
    assert!(netem.is_some());
    
    // Clean up
    conn.delete_link("test0").await.unwrap();
}
```

### 3.4 Tier 3: Functional Tests (Shell Scripts)

**Priority: MEDIUM** - For verifying CLI compatibility.

#### Directory Structure
```
tests/
├── Makefile
├── lib/
│   └── helpers.sh
├── ip/
│   ├── link_basic.t
│   ├── addr_basic.t
│   └── route_basic.t
└── tc/
    ├── qdisc_basic.t
    └── netem.t
```

#### Example Test Script
```bash
#!/bin/bash
# tests/tc/netem.t
. lib/helpers.sh

DEV="$(rand_dev)"

# Setup
rip_ip link add "$DEV" type dummy
rip_ip link set "$DEV" up

# Test: Add netem with delay
rip_tc qdisc add dev "$DEV" root netem delay 100ms
test_ok "Add netem qdisc"

# Verify
rip_tc qdisc show dev "$DEV" | grep -q "netem"
test_ok "Netem qdisc visible"

rip_tc qdisc show dev "$DEV" | grep -q "delay 100"
test_ok "Delay value correct"

# Test: Modify netem
rip_tc qdisc change dev "$DEV" root netem delay 50ms loss 1%
test_ok "Change netem qdisc"

rip_tc qdisc show dev "$DEV" | grep -q "delay 50"
test_ok "New delay value correct"

# Cleanup
rip_ip link del "$DEV"
test_ok "Cleanup"
```

#### Makefile
```makefile
RIP_IP := ../../target/release/ip
RIP_TC := ../../target/release/tc
PREFIX := sudo -E unshare -n

.PHONY: test
test: build
	@for t in ip/*.t tc/*.t; do \
		echo "Running $$t..."; \
		IP="$(RIP_IP)" TC="$(RIP_TC)" $(PREFIX) bash $$t || exit 1; \
	done

build:
	cargo build --release
```

### 3.5 Compatibility Testing with iproute2

For ensuring rip output matches iproute2:

```bash
#!/bin/bash
# tests/compat/link_show.t
# Compare rip output with iproute2

DEV="$(rand_dev)"
ip link add "$DEV" type dummy

# Run both and compare
IPROUTE2_OUT=$(ip -j link show "$DEV")
RIP_OUT=$(rip_ip -j link show "$DEV")

# Compare JSON structure (field by field)
compare_json "$IPROUTE2_OUT" "$RIP_OUT" "ifname"
compare_json "$IPROUTE2_OUT" "$RIP_OUT" "mtu"
compare_json "$IPROUTE2_OUT" "$RIP_OUT" "operstate"

ip link del "$DEV"
```

---

## 4. Implementation Priorities

### Phase 1: Immediate (No Infrastructure Changes)

1. **Add CLI argument parsing tests** to `bins/ip` and `bins/tc`
   - Test all subcommand combinations
   - Verify error messages for invalid input
   - ~200 tests across both binaries

2. **Add message fixture tests** to `rip-netlink`
   - Capture real netlink messages from kernel
   - Test parsing against known good data
   - ~50 fixtures for common message types

3. **Expand unit test coverage** for edge cases
   - Error paths in parsing
   - Boundary conditions (max values, empty strings)
   - ~100 additional tests

### Phase 2: Integration Infrastructure

1. **Create integration test harness**
   - Feature flag `integration` for privileged tests
   - Helper module for namespace setup/teardown
   - CI configuration for running with sudo

2. **Write core integration tests**
   - Link create/delete/modify
   - Address add/delete
   - Route add/delete
   - Qdisc add/delete/change

### Phase 3: Functional Test Suite

1. **Port relevant iproute2 tests**
   - Adapt shell scripts for rip binaries
   - Focus on commonly used features first

2. **Add compatibility tests**
   - Compare JSON output with iproute2
   - Verify command-line compatibility

---

## 5. CI/CD Configuration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --all

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - run: sudo cargo test --all --features integration

  functional-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - run: cd tests && sudo make test
```

---

## 6. Summary

| Metric | Current | Target |
|--------|---------|--------|
| Unit tests | 53 | 200+ |
| Integration tests | 0 | 50+ |
| Functional tests | 0 | 20+ |
| Code coverage | ~15% | 60%+ |
| CI pipeline | Build only | Full test suite |

### Key Takeaways

1. **iproute2's approach is pragmatic**: Shell scripts + network namespaces provide excellent isolation without complex infrastructure.

2. **rip has good foundation**: Unit tests for core libraries exist, but binary commands have no tests.

3. **Three-tier approach is best**: Unit tests for logic, integration tests for netlink, functional tests for CLI.

4. **Network namespaces are essential**: `unshare -n` provides isolated testing without affecting host.

5. **Netlink message fixtures are valuable**: Pre-captured binary messages test parsing without kernel.
