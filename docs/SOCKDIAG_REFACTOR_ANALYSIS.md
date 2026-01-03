# SockDiag Refactor Analysis: Should It Use Connection<P>?

## Current State

### `sockdiag` Module (Separate Implementation)
- **File**: `crates/nlink/src/sockdiag/connection.rs`
- **Struct**: `SockDiag`
- **Socket handling**: Raw `libc::socket()`, manual `AsyncFd<RawFd>`
- **Error type**: Separate `sockdiag::Error`
- **Lines of code**: ~700 lines

### `netlink` Module (Connection Pattern)
- **Files**: `socket.rs`, `connection.rs`, `protocol.rs`
- **Struct**: `Connection<P: ProtocolState>`
- **Socket handling**: Uses `netlink-sys` crate, `AsyncFd<Socket>`
- **Error type**: `netlink::Error`
- **Shared infrastructure**: `MessageBuilder`, `MessageIter`, `AttrIter`

## Code Duplication Analysis

| Functionality | sockdiag | netlink | Duplicated? |
|---------------|----------|---------|-------------|
| Socket creation | Raw libc | netlink-sys | **Yes** |
| Non-blocking setup | Manual fcntl | netlink-sys | **Yes** |
| Namespace support | None | Full support | **Missing in sockdiag** |
| Sequence number tracking | Manual u32 | AtomicU32 | Similar |
| Send/recv async | Manual poll | Manual poll | **Yes** |
| Message building | Manual bytes | MessageBuilder | **Different** |
| Attribute parsing | Manual | AttrIter | **Different** |
| Error handling | sockdiag::Error | netlink::Error | **Separate types** |

### Duplicated Code (~200 lines)
```rust
// sockdiag: Socket creation (lines 65-130)
let fd = unsafe {
    libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_SOCK_DIAG)
};
// bind, getsockname, fcntl for non-blocking...

// netlink: Uses netlink-sys which does the same internally
let socket = Socket::new(protocol.as_isize())?;
socket.bind_auto()?;
socket.set_non_blocking(true)?;
```

```rust
// sockdiag: Send/recv (lines 650-700)
async fn send(&self, data: &[u8]) -> Result<()> {
    loop {
        let mut guard = self.fd.writable().await?;
        match guard.try_io(|inner| { libc::send(...) }) { ... }
    }
}

// netlink: Very similar pattern (socket.rs lines 200-250)
pub async fn send(&self, data: &[u8]) -> Result<usize> {
    loop {
        let mut guard = self.fd.writable().await?;
        match guard.try_io(|_| self.fd.get_ref().send(...)) { ... }
    }
}
```

## What Would Change with Refactor

### Option A: Full Integration (Connection<SockDiag>)

**Add to `protocol.rs`:**
```rust
#[derive(Debug, Default, Clone, Copy)]
pub struct SockDiag;

impl private::Sealed for SockDiag {}

impl ProtocolState for SockDiag {
    const PROTOCOL: Protocol = Protocol::SockDiag;  // Add to enum
}
```

**Add to `socket.rs`:**
```rust
pub enum Protocol {
    Route,
    Generic,
    SockDiag,  // Add this
    // ...
}
```

**Move sockdiag methods to `Connection<SockDiag>`:**
```rust
impl Connection<SockDiag> {
    pub async fn query_tcp(&self) -> Result<Vec<InetSocket>> { ... }
    pub async fn query_udp(&self) -> Result<Vec<InetSocket>> { ... }
    pub async fn query_unix(&self) -> Result<Vec<UnixSocket>> { ... }
    // ...
}
```

### Option B: Shared Socket Only

Keep `SockDiag` as separate struct but use `NetlinkSocket` internally:
```rust
pub struct SockDiag {
    socket: NetlinkSocket,  // Instead of raw fd
}

impl SockDiag {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new(Protocol::SockDiag)?,
        })
    }
    
    pub async fn new_in_namespace(name: &str) -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new_in_namespace_path(
                Protocol::SockDiag,
                format!("/var/run/netns/{}", name)
            )?,
        })
    }
}
```

### Option C: Keep Separate (Status Quo)

No changes. Accept duplication.

## Comparison Matrix

| Criteria | Option A (Full) | Option B (Socket) | Option C (Separate) |
|----------|-----------------|-------------------|---------------------|
| Code reduction | ~300 lines | ~150 lines | 0 |
| API consistency | High | Medium | Low |
| Namespace support | Free | Free | Must add manually |
| Breaking change | **Yes** | No | No |
| Implementation effort | High (2-3 days) | Low (1 day) | None |
| Error type unification | Yes | No | No |
| Feature flag preserved | Yes | Yes | Yes |

## Breaking Changes with Option A

```rust
// Before
use nlink::sockdiag::{SockDiag, InetFilter};
let diag = SockDiag::new().await?;
let sockets = diag.query_tcp().await?;

// After  
use nlink::netlink::{Connection, SockDiag};
use nlink::sockdiag::{InetFilter};  // Types stay here
let conn = Connection::<SockDiag>::new()?;
let sockets = conn.query_tcp().await?;
```

## Missing Features in sockdiag

Currently `sockdiag` lacks:
1. **Namespace support** - Cannot query sockets in other namespaces
2. **Netlink socket diagnostics** - `query_netlink()` returns empty
3. **Packet socket diagnostics** - `query_packet()` returns empty

With refactor, namespace support comes for free.

## Recommendation

### **Option B: Shared Socket (Recommended)**

**Rationale:**
1. **Low risk** - No public API changes
2. **Immediate benefit** - Namespace support for sockdiag
3. **Code reduction** - Eliminates ~150 lines of socket boilerplate
4. **Incremental** - Can do full integration (Option A) later if needed

**Implementation plan:**
1. Add `Protocol::SockDiag` to the enum
2. Change `SockDiag` to use `NetlinkSocket` internally
3. Keep all public types (`InetSocket`, `TcpInfo`, etc.) in `sockdiag` module
4. Add `SockDiag::new_in_namespace()` method

**Why not Option A:**
- Breaking change for a feature-gated module
- SOCK_DIAG message format is very different from RTNetlink
- `MessageBuilder`/`AttrIter` don't map well to inet_diag structures
- Benefit vs effort ratio is low

## Effort Estimate

| Task | Option A | Option B |
|------|----------|----------|
| Add Protocol::SockDiag | 10 min | 10 min |
| Refactor SockDiag struct | 2 hours | 30 min |
| Add namespace methods | Free | 15 min |
| Update tests | 1 hour | 15 min |
| Update documentation | 30 min | 15 min |
| **Total** | **4+ hours** | **~1.5 hours** |

## Conclusion

**Recommended action:** Implement **Option B** (shared socket layer).

This provides:
- Namespace support for `sockdiag` (currently missing)
- Reduced code duplication (~150 lines)
- No breaking changes
- Path to full integration later if desired

The full `Connection<SockDiag>` integration (Option A) is not worth the breaking change since the message formats are quite different and don't benefit much from `MessageBuilder`/`AttrIter`.
