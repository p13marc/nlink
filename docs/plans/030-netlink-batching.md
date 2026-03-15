# Plan 030: Netlink Batching / Bulk Operations

## Overview

Add support for sending multiple netlink messages in a single `sendmsg()` and collecting per-message ACKs. For 1000 routes, this reduces 1000 syscall round-trips to 1.

This is **not** `FuturesUnordered`/`JoinSet` concurrency (which still does 1 message per syscall). True batching concatenates messages in a single kernel buffer.

## Design

### API

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::route::Ipv4Route;

let conn = Connection::<Route>::new()?;

// Build a batch of operations
let results = conn.batch()
    .add_route(Ipv4Route::new("10.0.0.0", 8).dev("eth0"))
    .add_route(Ipv4Route::new("10.1.0.0", 16).dev("eth0"))
    .del_link("old0")
    .execute()
    .await?;

// Per-operation results
for (i, result) in results.iter().enumerate() {
    match result {
        Ok(()) => {}
        Err(e) if e.is_not_found() => eprintln!("op {i}: not found"),
        Err(e) => return Err(e.clone()),
    }
}

// Or fail on first error
conn.batch()
    .add_route(route1)
    .add_route(route2)
    .execute_all()
    .await?;
```

### Internal Implementation

```rust
pub struct Batch<'a> {
    conn: &'a Connection<Route>,
    ops: Vec<BatchOp>,
}

struct BatchOp {
    seq: u32,
    msg: Vec<u8>,
}

impl<'a> Batch<'a> {
    /// Execute all operations in a single sendmsg().
    /// Returns one Result per operation.
    pub async fn execute(self) -> Result<Vec<Result<()>>> {
        if self.ops.is_empty() {
            return Ok(vec![]);
        }

        // Concatenate all messages (each already NLA-aligned)
        let mut buf = Vec::with_capacity(self.ops.iter().map(|o| o.msg.len()).sum());
        for op in &self.ops {
            buf.extend_from_slice(&op.msg);
        }

        // Send all at once
        self.conn.socket().send(&buf).await?;

        // Collect ACKs matched by sequence number
        let mut results: Vec<Option<Result<()>>> = vec![None; self.ops.len()];
        let mut remaining = self.ops.len();

        while remaining > 0 {
            let response = self.conn.socket().recv_msg().await?;
            for msg in MessageIter::new(&response) {
                let seq = msg.seq();
                if let Some(idx) = self.ops.iter().position(|op| op.seq == seq) {
                    if results[idx].is_none() {
                        results[idx] = Some(self.conn.parse_ack_result(&msg));
                        remaining -= 1;
                    }
                }
            }
        }

        Ok(results.into_iter().map(|r| r.unwrap_or(Ok(()))).collect())
    }

    /// Execute all operations, returning the first error encountered.
    pub async fn execute_all(self) -> Result<()> {
        for result in self.execute().await? {
            result?;
        }
        Ok(())
    }
}
```

### Auto-Splitting

The socket send buffer (`SO_SNDBUF`, default ~212KB) limits batch size. Auto-split:

```rust
const MAX_BATCH_SIZE: usize = 200 * 1024; // Conservative 200KB

pub async fn execute(self) -> Result<Vec<Result<()>>> {
    let mut all_results = Vec::with_capacity(self.ops.len());
    let mut chunk_start = 0;
    let mut chunk_size = 0;

    for (i, op) in self.ops.iter().enumerate() {
        if chunk_size + op.msg.len() > MAX_BATCH_SIZE && chunk_size > 0 {
            // Send current chunk
            all_results.extend(self.send_chunk(&self.ops[chunk_start..i]).await?);
            chunk_start = i;
            chunk_size = 0;
        }
        chunk_size += op.msg.len();
    }

    // Send remaining
    if chunk_start < self.ops.len() {
        all_results.extend(self.send_chunk(&self.ops[chunk_start..]).await?);
    }

    Ok(all_results)
}
```

### Builder Methods

Each method internally builds a message with a unique sequence number, exactly as the existing `send_ack` methods do, but buffers instead of sending:

```rust
impl<'a> Batch<'a> {
    pub fn add_route(mut self, route: impl Into<RouteConfig>) -> Self {
        let seq = self.conn.socket().next_seq();
        let builder = self.conn.build_add_route(route.into());
        // finalize with seq
        self.ops.push(BatchOp { seq, msg: builder.finish_with_seq(seq) });
        self
    }

    pub fn del_link(mut self, name: impl Into<InterfaceRef>) -> Self { /* ... */ }
    pub fn add_link(mut self, config: impl LinkConfig) -> Self { /* ... */ }
    pub fn add_address(mut self, addr: impl AddressConfig) -> Self { /* ... */ }
    pub fn del_address(mut self, addr: impl AddressConfig) -> Self { /* ... */ }
    pub fn add_neighbor(mut self, neigh: impl NeighborConfig) -> Self { /* ... */ }
    pub fn add_fdb(mut self, entry: FdbEntryBuilder) -> Self { /* ... */ }
}
```

This requires extracting the message-building logic from current `send_ack`-based methods into standalone `build_*` methods, which is a refactor of `connection.rs`.

## Files to Modify

1. `crates/nlink/src/netlink/batch.rs` (new) - `Batch` struct and execute logic
2. `crates/nlink/src/netlink/connection.rs` - Add `batch()`, extract `build_*` methods
3. `crates/nlink/src/netlink/mod.rs` - Export batch module

## Estimated Effort

| Task | Effort |
|------|--------|
| Extract build methods from connection.rs | 2 days |
| Batch core (concat, send, ACK matching) | 2 days |
| Auto-splitting | 1 day |
| Route/link/addr/fdb batch methods | 2 days |
| Integration tests | 1 day |
| **Total** | ~1.5 weeks |

## Notes

- Kernel processes batched messages **sequentially** (order preserved)
- Each message gets its own ACK -- errors don't stop subsequent messages
- This is orthogonal to nftables batch transactions (which use `NFNL_MSG_BATCH_BEGIN/END` for atomicity)
