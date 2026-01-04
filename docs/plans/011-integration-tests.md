# Plan 011: Integration Tests Infrastructure

## Overview

Create an integration test framework using network namespaces for isolated, reproducible testing of netlink operations.

## Motivation

Current testing limitations:
- Unit tests only cover parsing, not actual netlink operations
- Manual testing requires root and affects system state
- No CI integration for netlink operations
- Difficult to test error conditions

## Design

### Test Infrastructure

```rust
// tests/common/mod.rs

use nlink::netlink::{Connection, Route, namespace};
use std::process::Command;

/// Test namespace with automatic cleanup.
pub struct TestNamespace {
    name: String,
}

impl TestNamespace {
    /// Create a new test namespace.
    pub fn new(name: &str) -> Result<Self> {
        Command::new("ip")
            .args(["netns", "add", name])
            .status()?;
        Ok(Self { name: name.into() })
    }
    
    /// Get a connection to this namespace.
    pub fn connection(&self) -> Result<Connection<Route>> {
        namespace::connection_for(&self.name)
    }
    
    /// Run a command in the namespace.
    pub fn exec(&self, cmd: &str, args: &[&str]) -> Result<String> {
        let output = Command::new("ip")
            .args(["netns", "exec", &self.name, cmd])
            .args(args)
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into())
    }
    
    /// Add veth pair connecting to another namespace.
    pub fn connect_to(&self, other: &TestNamespace, 
                       local_name: &str, remote_name: &str) -> Result<()>;
}

impl Drop for TestNamespace {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .status();
    }
}

/// Skip test if not running as root.
#[macro_export]
macro_rules! require_root {
    () => {
        if !nix::unistd::geteuid().is_root() {
            eprintln!("Skipping test: requires root");
            return Ok(());
        }
    };
}
```

### Test Categories

```
tests/
  common/
    mod.rs           # Test utilities
  integration/
    link.rs          # Link creation/deletion tests
    address.rs       # Address management tests
    route.rs         # Route management tests
    tc.rs            # TC qdisc/class/filter tests
    namespace.rs     # Namespace operations tests
    events.rs        # Event monitoring tests
```

### Example Tests

```rust
// tests/integration/link.rs

use nlink_test::TestNamespace;

#[tokio::test]
async fn test_create_veth_pair() -> Result<()> {
    require_root!();
    
    let ns = TestNamespace::new("test-veth")?;
    let conn = ns.connection()?;
    
    // Create veth pair
    conn.add_link(VethLink::new("veth0", "veth1")).await?;
    
    // Verify
    let links = conn.get_links().await?;
    assert!(links.iter().any(|l| l.name() == Some("veth0")));
    assert!(links.iter().any(|l| l.name() == Some("veth1")));
    
    // Delete
    conn.del_link("veth0").await?;
    
    // Verify deleted
    let links = conn.get_links().await?;
    assert!(!links.iter().any(|l| l.name() == Some("veth0")));
    
    Ok(())
}

#[tokio::test]
async fn test_htb_hierarchy() -> Result<()> {
    require_root!();
    
    let ns = TestNamespace::new("test-htb")?;
    let conn = ns.connection()?;
    
    // Setup
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    
    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", "1:", htb).await?;
    
    // Add classes
    conn.add_class("dummy0", "1:0", "1:1", "htb",
        &["rate", "100mbit"]).await?;
    conn.add_class("dummy0", "1:1", "1:10", "htb",
        &["rate", "10mbit", "ceil", "50mbit"]).await?;
    
    // Verify
    let classes = conn.get_classes_for("dummy0").await?;
    assert_eq!(classes.len(), 2);
    
    Ok(())
}
```

### CI Integration

```yaml
# .github/workflows/integration.yml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-action@stable
      
      - name: Run integration tests
        run: |
          sudo cargo test --test integration -- --test-threads=1
```

## Implementation Steps

1. Create `tests/common/mod.rs` with `TestNamespace` helper
2. Create `tests/integration/` directory structure
3. Write link tests (veth, bridge, dummy, vlan)
4. Write address tests (add, del, replace)
5. Write route tests (add, del, ECMP)
6. Write TC tests (qdisc, class, filter)
7. Write event monitoring tests
8. Add CI workflow

## Effort Estimate

- Infrastructure: ~3 hours
- Link tests: ~2 hours
- Address/route tests: ~2 hours
- TC tests: ~3 hours
- Event tests: ~2 hours
- CI setup: ~1 hour
- **Total: ~13 hours**
