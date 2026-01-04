# Plan 001: Expose TC Class API on Connection

## Overview

Expose the existing TC class management functions from `tc/builders/class.rs` as methods on `Connection<Route>`, providing a consistent API alongside qdisc and filter operations.

## Motivation

Currently, TC class operations exist in `crates/nlink/src/tc/builders/class.rs` but are not exposed on `Connection<Route>`. Users must either:
1. Use the low-level `tc::builders::class::add()` function directly
2. Build raw netlink messages manually

This is inconsistent with qdisc and filter operations which have convenient `Connection` methods.

## Design

### API Design

```rust
impl Connection<Route> {
    /// Add a TC class.
    ///
    /// # Example
    /// ```ignore
    /// use nlink::netlink::{Connection, Route};
    /// 
    /// let conn = Connection::<Route>::new()?;
    /// 
    /// // Add HTB class with rate 10mbit, ceil 100mbit
    /// conn.add_class("eth0", "1:0", "1:10", "htb", 
    ///     &["rate", "10mbit", "ceil", "100mbit"]).await?;
    /// ```
    pub async fn add_class(
        &self,
        dev: &str,
        parent: &str,
        classid: &str,
        kind: &str,
        params: &[&str],
    ) -> Result<()>;

    /// Delete a TC class.
    pub async fn del_class(
        &self,
        dev: &str,
        parent: &str,
        classid: &str,
    ) -> Result<()>;

    /// Change a TC class's parameters.
    pub async fn change_class(
        &self,
        dev: &str,
        parent: &str,
        classid: &str,
        kind: &str,
        params: &[&str],
    ) -> Result<()>;

    /// Replace a TC class (add or update).
    pub async fn replace_class(
        &self,
        dev: &str,
        parent: &str,
        classid: &str,
        kind: &str,
        params: &[&str],
    ) -> Result<()>;

    // By-index variants for namespace operations
    pub async fn add_class_by_index(...) -> Result<()>;
    pub async fn del_class_by_index(...) -> Result<()>;
    pub async fn change_class_by_index(...) -> Result<()>;
    pub async fn replace_class_by_index(...) -> Result<()>;
}
```

### Implementation Details

The implementation will delegate to the existing `tc::builders::class` module functions. The main work is:

1. Add wrapper methods to `Connection<Route>` in `netlink/connection.rs`
2. Convert `&[&str]` to `Vec<String>` for the existing API
3. Add `*_by_index` variants that skip ifname lookup

### File Changes

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/connection.rs` | Add class methods to `impl Connection<Route>` |
| `crates/nlink/src/netlink/mod.rs` | Ensure `tc::builders::class` is accessible |
| `crates/nlink/src/lib.rs` | No changes needed (re-exports Connection) |

## Implementation Steps

### Step 1: Add class methods to Connection

In `crates/nlink/src/netlink/connection.rs`, add to the `impl Connection<Route>` block:

```rust
// ============================================================================
// TC Class Operations
// ============================================================================

/// Add a TC class.
pub async fn add_class(
    &self,
    dev: &str,
    parent: &str,
    classid: &str,
    kind: &str,
    params: &[&str],
) -> Result<()> {
    let params: Vec<String> = params.iter().map(|s| s.to_string()).collect();
    crate::tc::builders::class::add(self, dev, parent, classid, kind, &params).await
}

/// Delete a TC class.
pub async fn del_class(
    &self,
    dev: &str,
    parent: &str,
    classid: &str,
) -> Result<()> {
    crate::tc::builders::class::del(self, dev, parent, classid).await
}

/// Change a TC class's parameters.
pub async fn change_class(
    &self,
    dev: &str,
    parent: &str,
    classid: &str,
    kind: &str,
    params: &[&str],
) -> Result<()> {
    let params: Vec<String> = params.iter().map(|s| s.to_string()).collect();
    crate::tc::builders::class::change(self, dev, parent, classid, kind, &params).await
}

/// Replace a TC class (add or update).
pub async fn replace_class(
    &self,
    dev: &str,
    parent: &str,
    classid: &str,
    kind: &str,
    params: &[&str],
) -> Result<()> {
    let params: Vec<String> = params.iter().map(|s| s.to_string()).collect();
    crate::tc::builders::class::replace(self, dev, parent, classid, kind, &params).await
}
```

### Step 2: Add by-index variants

Add variants that take `ifindex: i32` instead of `dev: &str` for namespace operations.

### Step 3: Update documentation

Add examples to CLAUDE.md showing the new API.

## Testing

### Manual Testing

```bash
# Create namespace for testing
sudo ip netns add test-class

# Run test
sudo ip netns exec test-class cargo run --example tc_class

# Cleanup
sudo ip netns del test-class
```

### Example Test Code

```rust
// examples/route/tc/class.rs
use nlink::netlink::{Connection, Route};
use nlink::netlink::tc::HtbQdiscConfig;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    // First, add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x10).build();
    conn.add_qdisc_full("lo", "root", "1:", htb).await?;
    
    // Add a class
    conn.add_class("lo", "1:0", "1:10", "htb", 
        &["rate", "1mbit", "ceil", "10mbit"]).await?;
    
    // Verify
    let classes = conn.get_classes_for("lo").await?;
    for class in &classes {
        println!("Class: {:x} parent {:x}", class.handle(), class.parent());
    }
    
    // Change class rate
    conn.change_class("lo", "1:0", "1:10", "htb",
        &["rate", "2mbit", "ceil", "10mbit"]).await?;
    
    // Delete class
    conn.del_class("lo", "1:0", "1:10").await?;
    
    // Cleanup
    conn.del_qdisc("lo", "root").await?;
    
    Ok(())
}
```

## Documentation

Update the following:

1. **CLAUDE.md**: Add TC class section under "Key Patterns"
2. **docs/library.md**: Add class examples if present
3. **Module docs**: Add examples to connection.rs

Example documentation addition:

```markdown
**TC class management:**
```rust
let conn = Connection::<Route>::new()?;

// Add HTB qdisc first
conn.add_qdisc_full("eth0", "root", "1:", htb_config).await?;

// Add classes
conn.add_class("eth0", "1:0", "1:1", "htb", 
    &["rate", "100mbit", "ceil", "1gbit"]).await?;
conn.add_class("eth0", "1:1", "1:10", "htb", 
    &["rate", "10mbit", "ceil", "100mbit"]).await?;

// Query classes
let classes = conn.get_classes_for("eth0").await?;

// Delete class
conn.del_class("eth0", "1:0", "1:10").await?;
```
```

## Effort Estimate

- Implementation: ~1 hour
- Testing: ~30 minutes
- Documentation: ~30 minutes
- **Total: ~2 hours**

## Future Work

After this plan, implement [Plan 004: HTB Class Typed Builder](./004-htb-class-builder.md) to provide a type-safe builder API instead of string parameters.
