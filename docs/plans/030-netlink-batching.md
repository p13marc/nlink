# Plan 030: Netlink Batching / Bulk Operations

## Overview

Add support for sending multiple netlink messages in a single `sendmsg()` and collecting per-message ACKs. For 1000 routes, this reduces 1000 syscall round-trips to ~5 (auto-split at 200KB).

This is **not** `FuturesUnordered`/`JoinSet` concurrency (which still does 1 message per syscall). True batching concatenates messages in a single kernel buffer.

## API

### Basic Usage

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::route::Ipv4Route;
use nlink::netlink::link::DummyLink;

let conn = Connection::<Route>::new()?;

// Build a batch of operations — each returns a typed per-op result
let results: BatchResults = conn.batch()
    .add_route(Ipv4Route::new("10.0.0.0", 8).dev("eth0"))
    .add_route(Ipv4Route::new("10.1.0.0", 16).dev("eth0"))
    .del_link("old0")
    .execute()
    .await?;

// Inspect per-operation results
for (i, result) in results.iter().enumerate() {
    match result {
        Ok(()) => {}
        Err(e) if e.is_not_found() => eprintln!("op {i}: not found (ignored)"),
        Err(e) => return Err(e.clone()),
    }
}

// Convenience: fail on first error
conn.batch()
    .add_route(route1)
    .add_route(route2)
    .execute_all()
    .await?;
```

### Bulk Route Loading (common use case)

```rust
use nlink::netlink::batch::Batch;

let conn = Connection::<Route>::new()?;

// Add 10,000 routes in batches (auto-split at 200KB)
let routes: Vec<Ipv4Route> = (0..10_000)
    .map(|i| Ipv4Route::new(format!("10.{}.{}.0", i / 256, i % 256), 24).dev("eth0"))
    .collect();

let mut batch = conn.batch();
for route in routes {
    batch = batch.add_route(route);
}
let results = batch.execute().await?;

let errors: Vec<_> = results.errors().collect();
if !errors.is_empty() {
    eprintln!("{} routes failed", errors.len());
}
```

## Design

### Core Types

```rust
/// A batch of netlink operations to execute in minimal syscalls.
///
/// Operations are buffered and sent as concatenated messages in a single
/// `sendmsg()`. The kernel processes them sequentially and returns one
/// ACK per message. Auto-splits at `MAX_BATCH_SIZE` to stay within
/// socket buffer limits.
pub struct Batch<'a> {
    conn: &'a Connection<Route>,
    ops: Vec<BatchOp>,
}

struct BatchOp {
    seq: u32,
    msg: Vec<u8>,
}

/// Results from a batch execution.
///
/// Contains one `Result<()>` per operation in submission order.
pub struct BatchResults {
    results: Vec<Result<()>>,
}

impl BatchResults {
    /// Iterate over all results.
    pub fn iter(&self) -> impl Iterator<Item = &Result<()>> {
        self.results.iter()
    }

    /// Iterate over only the errors.
    pub fn errors(&self) -> impl Iterator<Item = (usize, &Error)> {
        self.results.iter().enumerate().filter_map(|(i, r)| {
            r.as_ref().err().map(|e| (i, e))
        })
    }

    /// Number of successful operations.
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_ok()).count()
    }

    /// Number of failed operations.
    pub fn error_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_err()).count()
    }

    /// True if all operations succeeded.
    pub fn all_ok(&self) -> bool {
        self.results.iter().all(|r| r.is_ok())
    }
}
```

### Builder Methods

Each builder method internally constructs a message with a unique sequence number and buffers it:

```rust
impl<'a> Batch<'a> {
    // Route operations
    pub fn add_route(mut self, route: impl Into<RouteConfig>) -> Self;
    pub fn del_route(mut self, route: impl Into<RouteConfig>) -> Self;
    pub fn replace_route(mut self, route: impl Into<RouteConfig>) -> Self;

    // Link operations
    pub fn add_link(mut self, config: impl LinkConfig) -> Self;
    pub fn del_link(mut self, iface: impl Into<InterfaceRef>) -> Self;
    pub fn set_link_up(mut self, iface: impl Into<InterfaceRef>) -> Self;
    pub fn set_link_down(mut self, iface: impl Into<InterfaceRef>) -> Self;

    // Address operations
    pub fn add_address(mut self, addr: impl AddressConfig) -> Self;
    pub fn del_address(mut self, addr: impl AddressConfig) -> Self;

    // Neighbor operations
    pub fn add_neighbor(mut self, neigh: impl NeighborConfig) -> Self;
    pub fn del_neighbor(mut self, neigh: impl NeighborConfig) -> Self;

    // FDB operations
    pub fn add_fdb(mut self, entry: FdbEntryBuilder) -> Self;
    pub fn del_fdb(mut self, entry: FdbEntryBuilder) -> Self;

    // TC operations
    pub fn add_qdisc(mut self, ifindex: u32, config: impl QdiscConfig) -> Self;
    pub fn del_qdisc(mut self, ifindex: u32, parent: &str) -> Self;

    /// Execute all operations, returning per-operation results.
    pub async fn execute(self) -> Result<BatchResults>;

    /// Execute all operations, returning the first error encountered.
    pub async fn execute_all(self) -> Result<()>;

    /// Number of buffered operations.
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}
```

### Internal: Message Building Refactor

Currently, `connection.rs` methods like `add_route()` build a message and immediately send it. To support batching, the message-building logic needs to be extractable:

```rust
impl Connection<Route> {
    // Existing (sends immediately):
    pub async fn add_route(&self, route: impl Into<RouteConfig>) -> Result<()> {
        let builder = self.build_add_route(route.into())?;
        self.send_ack(builder).await
    }

    // New (build only, for batching):
    pub(crate) fn build_add_route(&self, route: RouteConfig) -> Result<MessageBuilder> {
        // Same logic as before, but returns builder instead of sending
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE as u16,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        route.write_to(&mut builder)?;
        Ok(builder)
    }
}
```

### Internal: Execute with Auto-Splitting

```rust
const MAX_BATCH_SIZE: usize = 200 * 1024; // 200KB (SO_SNDBUF default ~212KB)

impl<'a> Batch<'a> {
    pub async fn execute(self) -> Result<BatchResults> {
        if self.ops.is_empty() {
            return Ok(BatchResults { results: vec![] });
        }

        let mut all_results = Vec::with_capacity(self.ops.len());
        let mut chunk_start = 0;
        let mut chunk_size = 0;

        for (i, op) in self.ops.iter().enumerate() {
            if chunk_size + op.msg.len() > MAX_BATCH_SIZE && chunk_size > 0 {
                let chunk_results = self.send_chunk(&self.ops[chunk_start..i]).await?;
                all_results.extend(chunk_results);
                chunk_start = i;
                chunk_size = 0;
            }
            chunk_size += op.msg.len();
        }

        // Send remaining chunk
        if chunk_start < self.ops.len() {
            let chunk_results = self.send_chunk(&self.ops[chunk_start..]).await?;
            all_results.extend(chunk_results);
        }

        Ok(BatchResults { results: all_results })
    }

    async fn send_chunk(&self, ops: &[BatchOp]) -> Result<Vec<Result<()>>> {
        // Concatenate messages
        let mut buf = Vec::with_capacity(ops.iter().map(|o| o.msg.len()).sum());
        for op in ops {
            buf.extend_from_slice(&op.msg);
        }

        // Single sendmsg()
        self.conn.socket().send(&buf).await?;

        // Collect ACKs matched by sequence number
        let mut results: Vec<Option<Result<()>>> = vec![None; ops.len()];
        let mut remaining = ops.len();

        while remaining > 0 {
            let response = self.conn.socket().recv_msg().await?;
            for msg in MessageIter::new(&response) {
                let seq = msg.seq();
                if let Some(idx) = ops.iter().position(|op| op.seq == seq) {
                    if results[idx].is_none() {
                        results[idx] = Some(self.conn.parse_ack_result(&msg));
                        remaining -= 1;
                    }
                }
            }
        }

        Ok(results.into_iter().map(|r| r.unwrap_or(Ok(()))).collect())
    }

    pub async fn execute_all(self) -> Result<()> {
        let results = self.execute().await?;
        for result in results.iter() {
            result.as_ref().map_err(|e| e.clone())?;
        }
        Ok(())
    }
}
```

### Error Handling

- Each operation gets its own `Result<()>` — a failure in one does not stop others
- `execute()` only returns `Err` for transport-level errors (socket failure)
- `execute_all()` returns the first per-operation error
- The `Error` type must implement `Clone` (add `#[derive(Clone)]` if missing)
- `BatchResults` provides `errors()` iterator for selective error handling

### Timeout Integration

If `Connection` has a timeout set (Plan 032), apply it to the entire batch execution, not per-operation:

```rust
pub async fn execute(self) -> Result<BatchResults> {
    self.conn.with_timeout(self.execute_inner()).await
}
```

## Files to Modify

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/batch.rs` (new) | `Batch`, `BatchOp`, `BatchResults` |
| `crates/nlink/src/netlink/connection.rs` | Add `batch()` method; extract `build_*` methods from existing `add_*/del_*` |
| `crates/nlink/src/netlink/mod.rs` | Export `batch` module |
| `crates/nlink/src/lib.rs` | Re-export `Batch`, `BatchResults` |

## Estimated Effort

| Task | Effort |
|------|--------|
| Extract `build_*` methods from connection.rs | 2 days |
| `Batch` core (concat, send, ACK matching) | 2 days |
| Auto-splitting | 0.5 day |
| `BatchResults` API | 0.5 day |
| Route/link/addr/fdb batch methods | 2 days |
| Integration tests | 1 day |
| **Total** | ~1.5 weeks |

## Notes

- Kernel processes batched messages **sequentially** (order preserved)
- Each message gets its own ACK — errors don't stop subsequent messages
- This is orthogonal to nftables batch transactions (Plan 033), which use `NFNL_MSG_BATCH_BEGIN/END` for atomicity
- `Error` needs `Clone` for `BatchResults` — currently `io::Error` prevents derive, may need `Arc<io::Error>` or a string snapshot
