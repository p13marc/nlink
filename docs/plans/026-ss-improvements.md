# Plan 026: `ss` Binary Improvements

## Overview

Improve the `nlink-ss` binary with missing features from iproute2's `ss`.

## Current State

The `ss` binary already supports:
- TCP, UDP, Unix, Raw, SCTP, MPTCP sockets
- State filters (-l, -a)
- Process info (-p), extended info (-e), memory (-m), TCP info (-i)
- Address/port filters (--src, --dst, --sport, --dport)
- JSON output (-j)

## Missing Features

| Feature | Priority | Effort |
|---------|----------|--------|
| `-s/--summary` | High | Small |
| `-K/--kill` | Medium | Medium |
| Netlink sockets | Low | Small |
| Expression filters | Low | Large |
| DCCP/VSOCK/TIPC | Low | Medium |

## Implementation Plan

### 1. Add Summary Mode (`-s`)

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

```rust
#[derive(Args)]
pub struct SsArgs {
    // ... existing args ...
    
    /// Show socket summary
    #[arg(short = 's', long)]
    summary: bool,
}

async fn run_summary(conn: &Connection<SockDiag>) -> Result<()> {
    let tcp = conn.tcp_sockets().all().query().await?;
    let udp = conn.udp_sockets().all().query().await?;
    let unix = conn.unix_sockets().all().query().await?;
    
    let tcp_estab = tcp.iter().filter(|s| s.state == TcpState::Established).count();
    let tcp_timewait = tcp.iter().filter(|s| s.state == TcpState::TimeWait).count();
    
    println!("Total: {}", tcp.len() + udp.len() + unix.len());
    println!("TCP:   {} (estab {}, timewait {})", tcp.len(), tcp_estab, tcp_timewait);
    println!("UDP:   {}", udp.len());
    println!("UNIX:  {}", unix.len());
    
    Ok(())
}
```

### 2. Add Kill Mode (`-K`)

Force close matching sockets (requires root, uses `SOCK_DESTROY`).

```bash
sudo ss -K dst 192.168.1.100
sudo ss -K sport = 8080
sudo ss -K state time-wait
```

```rust
#[derive(Args)]
pub struct SsArgs {
    // ... existing args ...
    
    /// Kill matching sockets
    #[arg(short = 'K', long)]
    kill: bool,
}

// In sockdiag module, add destroy capability
impl Connection<SockDiag> {
    pub async fn destroy_socket(&self, socket: &TcpSocket) -> Result<()> {
        // Send SOCK_DESTROY message
        let mut builder = self.create_request(SOCK_DESTROY)?;
        // ... build destroy request ...
        self.request_ack(builder).await
    }
}
```

**Note:** Socket destruction requires `CAP_NET_ADMIN` and kernel support.

### 3. Add Netlink Socket Listing

List netlink sockets (useful for debugging netlink applications).

```bash
ss --netlink
ss -n --netlink
```

```rust
#[derive(Args)]
pub struct SsArgs {
    // ... existing args ...
    
    /// Show netlink sockets
    #[arg(long)]
    netlink: bool,
}

// Netlink sockets use NETLINK_SOCK_DIAG with AF_NETLINK
```

Output:
```
Netlink   Recv-Q Send-Q   Local Address:Port   Peer Address:Port
nl        0      0        rtnl:1234            *
nl        0      0        generic:5678         *
```

### 4. Expression Filters (Future)

Full boolean expression support like iproute2:

```bash
ss 'sport = :22 or dport = :22'
ss 'dst 192.168.0.0/16 and state established'
ss '( sport = :80 or sport = :443 ) and state listening'
```

This requires implementing a mini expression parser.

```rust
// Expression AST
enum Expr {
    Sport(Comparison, u16),
    Dport(Comparison, u16),
    Src(IpNetwork),
    Dst(IpNetwork),
    State(TcpState),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

enum Comparison {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

fn parse_filter(input: &str) -> Result<Expr> {
    // Use winnow or nom to parse expressions
}

fn matches(socket: &TcpSocket, expr: &Expr) -> bool {
    match expr {
        Expr::Sport(cmp, port) => compare(socket.local_port, *cmp, *port),
        Expr::And(a, b) => matches(socket, a) && matches(socket, b),
        Expr::Or(a, b) => matches(socket, a) || matches(socket, b),
        // ...
    }
}
```

**Effort:** Large - requires expression parser and evaluator.

## Implementation Order

### Phase 1 (Quick)

1. Add `-s/--summary` flag
2. Update help text and documentation

### Phase 2 (Medium)

3. Add `--netlink` flag for netlink sockets
4. Add `-K/--kill` for socket destruction

### Phase 3 (Future)

5. Expression filter parser
6. DCCP/VSOCK/TIPC socket types

## Files to Modify

1. `bins/ss/src/main.rs` - Add new flags
2. `bins/ss/src/output.rs` - Summary output format
3. `crates/nlink/src/sockdiag/mod.rs` - Add destroy, netlink queries

## Testing

```bash
# Summary
./target/release/ss -s

# Kill (requires root)
sudo ./target/release/ss -K state time-wait

# Netlink sockets
./target/release/ss --netlink
```

## Estimated Effort

| Feature | Effort |
|---------|--------|
| Summary mode | 2 hours |
| Kill mode | 4 hours |
| Netlink sockets | 3 hours |
| Expression filters | 1-2 days |
| Total (Phase 1-2) | 1 day |

## Dependencies

- `nlink::sockdiag` module
- Kernel support for `SOCK_DESTROY` (Linux 4.9+)
