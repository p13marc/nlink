# Plan 026: `ss` Binary Improvements

## Overview

Improve the `nlink-ss` binary with missing features from iproute2's `ss`. All new library-level APIs must be strongly typed, async, and provide good error messages.

## Progress

### Phase 1: Summary Mode
- [x] Implement `SocketSummary` and `TcpSummary` types in `sockdiag`
- [x] Implement `socket_summary()` on `Connection<SockDiag>`
- [ ] Add unit tests for `SocketSummary` aggregation
- [ ] Add integration test querying real sockets
- [x] Add `-s` flag to `bins/ss` binary
- [x] Add summary output formatting in `bins/ss/src/output.rs`
- [x] Add doc comments with examples on all public types
- [ ] Update CLAUDE.md with `socket_summary()` usage example

### Phase 2: Kill Mode
- [x] Implement `destroy_tcp_socket()` on `Connection<SockDiag>`
- [x] Implement `destroy_matching()` with `DestroyResult`/`DestroyError`
- [x] Add `DestroyResult`, `DestroyError` types
- [ ] Add integration test (requires CAP_NET_ADMIN)
- [x] Add `-K` flag to `bins/ss` binary
- [x] Add doc comments with examples on destroy methods
- [ ] Update CLAUDE.md with kill mode example

### Phase 3: Netlink Socket Listing
- [ ] Implement `NetlinkSocketInfo` and `NetlinkProtocol` types
- [ ] Implement `netlink_sockets()` on `Connection<SockDiag>`
- [ ] Add integration test for netlink socket listing
- [ ] Add `--netlink` flag to `bins/ss` binary
- [ ] Add netlink socket output formatting
- [ ] Add doc comments with examples

### Phase 4: Expression Filters
- [ ] Implement `FilterExpr`, `Comparison` types
- [ ] Implement `FilterExpr::parse()` with winnow
- [ ] Implement `FilterExpr::matches()` evaluation
- [ ] Add unit tests for expression parsing and evaluation
- [ ] Add expression filter argument to `bins/ss` binary
- [ ] Add doc comments with examples

## Current State

The `ss` binary already supports:
- TCP, UDP, Unix, Raw, SCTP, MPTCP sockets
- State filters (`-l`, `-a`)
- Process info (`-p`), extended info (`-e`), memory (`-m`), TCP info (`-i`)
- Address/port filters (`--src`, `--dst`, `--sport`, `--dport`)
- JSON output (`-j`)

## Implementation Plan

### Phase 1: Summary Mode (`-s`)

Show socket statistics summary without listing individual sockets.

```bash
ss -s
```

Output:
```
Total: 234
TCP:   45 (estab 23, closed 12, orphaned 0, timewait 8)
UDP:   12
RAW:   2
UNIX:  175
```

**Library API** — Add a typed `SocketSummary` struct to `sockdiag`:

```rust
/// Aggregated socket statistics.
#[derive(Debug, Clone, Default)]
pub struct SocketSummary {
    pub tcp: TcpSummary,
    pub udp: u32,
    pub raw: u32,
    pub unix: u32,
}

#[derive(Debug, Clone, Default)]
pub struct TcpSummary {
    pub total: u32,
    pub established: u32,
    pub syn_sent: u32,
    pub syn_recv: u32,
    pub fin_wait1: u32,
    pub fin_wait2: u32,
    pub time_wait: u32,
    pub close: u32,
    pub close_wait: u32,
    pub last_ack: u32,
    pub listen: u32,
    pub closing: u32,
}

impl Connection<SockDiag> {
    /// Get aggregated socket statistics across all families.
    pub async fn socket_summary(&self) -> Result<SocketSummary> {
        let tcp = self.tcp_sockets().all().query().await?;
        let udp = self.udp_sockets().all().query().await?;
        let unix = self.unix_sockets().all().query().await?;

        let mut summary = SocketSummary {
            udp: udp.len() as u32,
            unix: unix.len() as u32,
            ..Default::default()
        };

        summary.tcp.total = tcp.len() as u32;
        for sock in &tcp {
            match sock.state {
                TcpState::Established => summary.tcp.established += 1,
                TcpState::TimeWait => summary.tcp.time_wait += 1,
                TcpState::Listen => summary.tcp.listen += 1,
                // ... other states
                _ => {}
            }
        }

        Ok(summary)
    }
}
```

### Phase 2: Kill Mode (`-K`)

Force close matching sockets using `SOCK_DESTROY` (Linux 4.9+, requires `CAP_NET_ADMIN`).

```bash
sudo ss -K dst 192.168.1.100
sudo ss -K sport = 8080
sudo ss -K state time-wait
```

**Library API** — Add `destroy_socket()` to `Connection<SockDiag>`:

```rust
/// Request to destroy (force-close) a socket.
///
/// The kernel sends a RST to the remote peer. Requires `CAP_NET_ADMIN`.
/// Only TCP sockets can be destroyed.
///
/// # Errors
///
/// Returns `Error::Kernel` with `EPERM` if insufficient privileges.
/// Returns `Error::Kernel` with `EOPNOTSUPP` if the socket type doesn't
/// support destruction.
impl Connection<SockDiag> {
    pub async fn destroy_tcp_socket(&self, socket: &TcpSocketInfo) -> Result<()> {
        let mut builder = self.build_destroy_request(socket)?;
        self.request_ack(builder).await
    }

    /// Destroy all TCP sockets matching the given filter.
    /// Returns the number of sockets destroyed.
    pub async fn destroy_matching(
        &self,
        filter: &SocketFilter,
    ) -> Result<DestroyResult> {
        let sockets = self.tcp_sockets().filter(filter).query().await?;
        let mut destroyed = 0u32;
        let mut errors = Vec::new();

        for sock in &sockets {
            match self.destroy_tcp_socket(sock).await {
                Ok(()) => destroyed += 1,
                Err(e) => errors.push(DestroyError {
                    socket: sock.id(),
                    error: e,
                }),
            }
        }

        Ok(DestroyResult { destroyed, errors })
    }
}

/// Result of a batch socket destruction operation.
#[derive(Debug)]
pub struct DestroyResult {
    pub destroyed: u32,
    pub errors: Vec<DestroyError>,
}

#[derive(Debug)]
pub struct DestroyError {
    pub socket: SocketId,
    pub error: Error,
}
```

Wire format: `SOCK_DESTROY` uses the same `inet_diag_req_v2` structure as `SOCK_DIAG_BY_FAMILY`, but with message type `SOCK_DESTROY_TCP` (= 21).

### Phase 3: Netlink Socket Listing

List netlink sockets (useful for debugging netlink applications).

```bash
ss --netlink
```

**Library API** — Add `NetlinkSocketInfo` to `sockdiag`:

```rust
/// Information about an open netlink socket.
#[derive(Debug, Clone)]
pub struct NetlinkSocketInfo {
    pub family: u8,
    pub protocol: NetlinkProtocol,
    pub port_id: u32,
    pub dst_port_id: u32,
    pub groups: u32,
    pub inode: u32,
    pub uid: u32,
}

/// Netlink protocol family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetlinkProtocol {
    Route,        // 0
    Unused,       // 1
    Usersock,     // 2
    Firewall,     // 3
    SockDiag,     // 4
    Nflog,        // 5
    Xfrm,         // 6
    SELinux,      // 7
    Iscsi,        // 8
    Audit,        // 9
    FibLookup,    // 10
    Connector,    // 11
    Netfilter,    // 12
    Ip6Fw,        // 13
    Dnrt,         // 14
    KobjectUevent, // 15
    Generic,      // 16
    ScsitTransport, // 18
    Ecryptfs,     // 19
    Rdma,         // 20
    Crypto,       // 21
    Smc,          // 22
    Unknown(u8),
}

impl Connection<SockDiag> {
    /// List all open netlink sockets.
    pub async fn netlink_sockets(&self) -> Result<Vec<NetlinkSocketInfo>> {
        // Uses NETLINK_SOCK_DIAG with AF_NETLINK family
        todo!()
    }
}
```

### Phase 4: Expression Filters (Future)

Full boolean expression support like iproute2:

```bash
ss 'sport = :22 or dport = :22'
ss 'dst 192.168.0.0/16 and state established'
ss '( sport = :80 or sport = :443 ) and state listening'
```

**Library API** — Typed filter expression AST:

```rust
/// Socket filter expression.
#[derive(Debug, Clone)]
pub enum FilterExpr {
    /// Match source port.
    Sport(Comparison, u16),
    /// Match destination port.
    Dport(Comparison, u16),
    /// Match source address/prefix.
    Src(IpNetwork),
    /// Match destination address/prefix.
    Dst(IpNetwork),
    /// Match TCP state.
    State(TcpState),
    /// Match process name.
    Process(String),
    /// Logical AND.
    And(Box<FilterExpr>, Box<FilterExpr>),
    /// Logical OR.
    Or(Box<FilterExpr>, Box<FilterExpr>),
    /// Logical NOT.
    Not(Box<FilterExpr>),
}

/// Comparison operator for port filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl FilterExpr {
    /// Parse a filter expression string (ss-compatible syntax).
    pub fn parse(input: &str) -> Result<Self> {
        // Use winnow for expression parsing
        todo!()
    }

    /// Evaluate this expression against a socket.
    pub fn matches(&self, socket: &TcpSocketInfo) -> bool {
        match self {
            Self::Sport(cmp, port) => cmp.apply(socket.local_port, *port),
            Self::Dport(cmp, port) => cmp.apply(socket.remote_port, *port),
            Self::State(state) => socket.state == *state,
            Self::And(a, b) => a.matches(socket) && b.matches(socket),
            Self::Or(a, b) => a.matches(socket) || b.matches(socket),
            Self::Not(inner) => !inner.matches(socket),
            _ => true,
        }
    }
}

impl Comparison {
    fn apply(&self, lhs: u16, rhs: u16) -> bool {
        match self {
            Self::Eq => lhs == rhs,
            Self::Ne => lhs != rhs,
            Self::Lt => lhs < rhs,
            Self::Le => lhs <= rhs,
            Self::Gt => lhs > rhs,
            Self::Ge => lhs >= rhs,
        }
    }
}
```

## Files to Modify

| File | Changes |
|------|---------|
| `crates/nlink/src/sockdiag/mod.rs` | `SocketSummary`, `socket_summary()`, `destroy_tcp_socket()`, `netlink_sockets()` |
| `crates/nlink/src/sockdiag/filter.rs` (new) | `FilterExpr`, `Comparison`, parser |
| `bins/ss/src/main.rs` | `-s`, `-K`, `--netlink` flags |
| `bins/ss/src/output.rs` | Summary output formatting |

## Estimated Effort

| Phase | Feature | Effort |
|-------|---------|--------|
| 1 | Summary mode (`-s`) | 2 hours |
| 2 | Kill mode (`-K`) | 4 hours |
| 3 | Netlink socket listing | 3 hours |
| 4 | Expression filters (future) | 1-2 days |
| | **Total (Phase 1-3)** | ~1 day |

## Notes

- `SOCK_DESTROY` requires `CAP_NET_ADMIN` and Linux 4.9+
- Only TCP sockets support destruction; UDP/Unix sockets cannot be force-closed
- Netlink socket diagnostics use `AF_NETLINK` family in `SOCK_DIAG_BY_FAMILY`
- Expression parser should use winnow (consistent with the rest of nlink)
