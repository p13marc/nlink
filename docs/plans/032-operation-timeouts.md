# Plan 032: Operation Timeout Support

## Overview

Add configurable timeouts for netlink operations. A hung kernel response currently blocks the caller forever.

## Current State

- `socket.rs`: `send()` and `recv_msg()` use tokio `AsyncFd` with no timeout
- `connection.rs`: `send_ack()` and `send_dump()` await indefinitely
- No `Error::Timeout` variant exists
- Users can manually wrap with `tokio::time::timeout()` but get `tokio::time::error::Elapsed` instead of `nlink::Error`

## Design: Stored Option on Connection

Following the reqwest pattern (connection-level default, per-operation override):

```rust
use nlink::{Connection, Route};
use std::time::Duration;

// Set a default timeout for all operations
let conn = Connection::<Route>::new()?
    .timeout(Duration::from_secs(5));

// All operations respect the default
let links = conn.get_links().await?;  // 5s timeout

// Users can still manually override with tokio::time::timeout
let links = tokio::time::timeout(
    Duration::from_secs(1),
    conn.get_links(),
).await.map_err(|_| nlink::Error::Timeout)??;
```

### Why Not `TimedConnection` Wrapper?

A wrapper type (`conn.with_timeout(dur).get_links()`) requires duplicating every method signature. The stored `Option<Duration>` approach is simpler:

- No new type needed
- No method duplication
- `None` = no timeout (backward compatible default)
- Applied at the lowest level (`send_ack`/`send_dump`) so all methods benefit

### Implementation

```rust
// In Connection<P>
pub struct Connection<P: ProtocolState> {
    socket: NetlinkSocket,
    state: P,
    timeout: Option<Duration>,  // NEW
}

impl<P: ProtocolState> Connection<P> {
    /// Set a default timeout for all operations.
    ///
    /// `None` means no timeout (the default). Operations that exceed the
    /// timeout return `Error::Timeout`.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Internal: wrap a future with the configured timeout.
    async fn with_timeout<F, T>(&self, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        match self.timeout {
            Some(dur) => tokio::time::timeout(dur, fut)
                .await
                .map_err(|_| Error::Timeout)?,
            None => fut.await,
        }
    }
}

// Apply in send_ack / send_dump:
pub(crate) async fn send_ack(&self, builder: MessageBuilder) -> Result<()> {
    self.with_timeout(self.send_ack_inner(builder)).await
}
```

### Error Variant

```rust
pub enum Error {
    // ... existing variants ...

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,
}

impl Error {
    /// Returns true if this error is a timeout.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout)
    }
}
```

## Files to Modify

1. `crates/nlink/src/netlink/connection.rs` - Add `timeout` field, `timeout()` builder, `with_timeout()` helper
2. `crates/nlink/src/netlink/error.rs` - Add `Timeout` variant and `is_timeout()` method

## Estimated Effort

| Task | Effort |
|------|--------|
| Add timeout field + builder | 30 min |
| `with_timeout()` wrapper | 30 min |
| Apply to send_ack/send_dump | 1 hour |
| Error variant | 15 min |
| Tests | 1 hour |
| **Total** | ~3-4 hours |
