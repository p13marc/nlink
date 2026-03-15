# Plan 032: Operation Timeout Support

## Overview

Add configurable timeouts for netlink operations. A hung kernel response currently blocks the caller indefinitely with no recourse.

## Progress

### Core Implementation
- [x] Add `timeout: Option<Duration>` field to `Connection<P>`
- [x] Implement `timeout()` builder method
- [x] Implement `no_timeout()` method
- [x] Implement `get_timeout()` method
- [x] Implement `with_timeout()` internal async helper

### Apply to Operations
- [x] Wrap `send_ack()` with `with_timeout()`
- [x] Wrap `send_dump()` with `with_timeout()`
- [x] Verify GENL connections propagate timeout
- [ ] Verify batch operations respect timeout (Plan 030)

### Error Variant
- [x] Add `Error::Timeout` variant to error enum
- [x] Implement `is_timeout()` method on `Error`
- [x] Add doc comments with examples on `Error::Timeout`

### Testing
- [x] Add test `test_no_timeout_default`
- [x] Add test `test_timeout_is_chainable`
- [x] Add test `test_timeout_respected` (short timeout)
- [x] Add integration test with actual timeout scenario

### Documentation
- [x] Add doc comments with examples on `timeout()` and `no_timeout()`
- [x] Update CLAUDE.md with timeout usage example

## Current State

- `socket.rs`: `send()` and `recv_msg()` use tokio `AsyncFd` with no timeout
- `connection.rs`: `send_ack()` and `send_dump()` await indefinitely
- No `Error::Timeout` variant exists
- Users must manually wrap with `tokio::time::timeout()` and convert the error

## Design: Stored `Option<Duration>` on Connection

Following the reqwest pattern — connection-level default, applied at the lowest level:

```rust
use nlink::{Connection, Route};
use std::time::Duration;

// Set a default timeout for all operations
let conn = Connection::<Route>::new()?
    .timeout(Duration::from_secs(5));

// All operations respect the default
let links = conn.get_links().await?;  // 5s timeout

// No timeout (default, backward compatible)
let conn = Connection::<Route>::new()?;
let links = conn.get_links().await?;  // waits indefinitely
```

### Why Not a Wrapper Type?

A wrapper `conn.with_timeout(dur).get_links()` requires duplicating every method. The stored `Option<Duration>` approach:

- No new type needed
- No method duplication
- `None` = no timeout (backward compatible default)
- Applied at `send_ack`/`send_dump` level so all methods benefit automatically

## Implementation

### Connection Changes

```rust
pub struct Connection<P: ProtocolState> {
    socket: NetlinkSocket,
    state: P,
    timeout: Option<Duration>,  // NEW
}

impl<P: ProtocolState> Connection<P> {
    /// Set a default timeout for all netlink operations.
    ///
    /// `None` means no timeout (the default). Operations that exceed the
    /// timeout return [`Error::Timeout`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::{Connection, Route};
    /// use std::time::Duration;
    ///
    /// let conn = Connection::<Route>::new()?
    ///     .timeout(Duration::from_secs(5));
    /// ```
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Clear the timeout (operations will wait indefinitely).
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Get the configured timeout.
    pub fn get_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Internal: wrap a future with the configured timeout.
    ///
    /// If no timeout is set, the future runs without time limit.
    /// On timeout, returns `Error::Timeout`.
    async fn with_timeout<F, T>(&self, fut: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        match self.timeout {
            Some(dur) => tokio::time::timeout(dur, fut)
                .await
                .map_err(|_| Error::Timeout)?,
            None => fut.await,
        }
    }
}
```

### Apply to Core Operations

```rust
impl<P: ProtocolState> Connection<P> {
    // Existing send_ack wraps its inner implementation:
    pub(crate) async fn send_ack(&self, builder: MessageBuilder) -> Result<()> {
        self.with_timeout(self.send_ack_inner(builder)).await
    }

    // Existing send_dump wraps its inner implementation:
    pub(crate) async fn send_dump<T: FromNetlink>(
        &self,
        builder: MessageBuilder,
    ) -> Result<Vec<T>> {
        self.with_timeout(self.send_dump_inner(builder)).await
    }
}
```

### Error Variant

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // ... existing variants ...

    /// Operation timed out.
    ///
    /// The configured timeout expired before the kernel responded.
    /// This typically indicates a kernel bug or an extremely loaded system.
    #[error("operation timed out")]
    Timeout,
}

impl Error {
    /// Returns true if this error is a timeout.
    ///
    /// # Example
    ///
    /// ```ignore
    /// match conn.get_links().await {
    ///     Err(e) if e.is_timeout() => eprintln!("kernel not responding"),
    ///     Err(e) => return Err(e),
    ///     Ok(links) => { /* ... */ }
    /// }
    /// ```
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout)
    }
}
```

### GENL Connections

GENL constructors (`new_async()`) should also propagate the timeout:

```rust
impl Connection<Ethtool> {
    pub async fn new_async() -> Result<Self> {
        // family resolution has no timeout (it's a one-time setup)
        let socket = NetlinkSocket::new(Ethtool::PROTOCOL)?;
        let (family_id, monitor_group_id) = resolve_ethtool_family(&socket).await?;
        let state = Ethtool { family_id, monitor_group_id };
        Ok(Self::from_parts(socket, state))
        // User calls .timeout() after construction:
        // Connection::<Ethtool>::new_async().await?.timeout(Duration::from_secs(5))
    }
}
```

### Batch Integration (Plan 030)

The timeout applies to the entire batch execution, not per-operation:

```rust
impl<'a> Batch<'a> {
    pub async fn execute(self) -> Result<BatchResults> {
        self.conn.with_timeout(self.execute_inner()).await
    }
}
```

## Files to Modify

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/connection.rs` | Add `timeout` field, `timeout()` builder, `no_timeout()`, `with_timeout()` helper; wrap `send_ack`/`send_dump` |
| `crates/nlink/src/netlink/error.rs` | Add `Timeout` variant and `is_timeout()` method |

## Integration Tests

```rust
#[tokio::test]
async fn test_timeout_respected() {
    let conn = Connection::<Route>::new()
        .unwrap()
        .timeout(Duration::from_millis(1)); // Extremely short

    // Normal operations should still work (kernel is fast)
    // This test verifies the plumbing, not actual timeouts
    let result = conn.get_links().await;
    // May succeed or timeout depending on system load
    if let Err(e) = &result {
        assert!(e.is_timeout());
    }
}

#[tokio::test]
async fn test_no_timeout_default() {
    let conn = Connection::<Route>::new().unwrap();
    assert_eq!(conn.get_timeout(), None);
}

#[tokio::test]
async fn test_timeout_is_chainable() {
    let conn = Connection::<Route>::new()
        .unwrap()
        .timeout(Duration::from_secs(5));
    assert_eq!(conn.get_timeout(), Some(Duration::from_secs(5)));

    let conn = conn.no_timeout();
    assert_eq!(conn.get_timeout(), None);
}
```

## Estimated Effort

| Task | Effort |
|------|--------|
| Add `timeout` field + builders | 30 min |
| `with_timeout()` wrapper | 30 min |
| Apply to `send_ack`/`send_dump` | 1 hour |
| `Error::Timeout` variant | 15 min |
| Tests | 1 hour |
| **Total** | ~3-4 hours |
