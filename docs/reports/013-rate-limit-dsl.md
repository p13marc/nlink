# Plan 013: Rate Limiting DSL - Completion Report

## Status: COMPLETED

## Summary

Implemented a high-level rate limiting API that abstracts away TC complexity for common bandwidth management use cases. The API provides two main types: `RateLimiter` for simple interface-wide rate limiting and `PerHostLimiter` for per-IP/per-subnet rate limiting.

## Implementation Details

### Files Created

| File | Purpose | Lines |
|------|---------|-------|
| `crates/nlink/src/netlink/ratelimit.rs` | Rate limiting DSL implementation | 960 |
| `crates/nlink/tests/integration/ratelimit.rs` | Integration tests | 311 |

**Total: 1,271 lines of code**

### Files Modified

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/mod.rs` | Added `pub mod ratelimit;` |
| `crates/nlink/tests/integration.rs` | Added ratelimit test module |
| `CLAUDE.md` | Added rate limiting documentation and examples |

### Core API

#### RateLimiter

Simple interface-wide rate limiting for egress and ingress traffic:

```rust
use nlink::netlink::ratelimit::RateLimiter;
use std::time::Duration;

// Simple rate limiting
RateLimiter::new("eth0")
    .egress("100mbit")?       // Limit upload
    .ingress("1gbit")?        // Limit download
    .burst_to("150mbit")?     // Allow bursting
    .latency(Duration::from_millis(20))  // AQM target
    .apply(&conn)
    .await?;

// Remove limits
RateLimiter::new("eth0")
    .remove(&conn)
    .await?;
```

#### PerHostLimiter

Per-IP or per-subnet rate limiting with customizable rules:

```rust
use nlink::netlink::ratelimit::PerHostLimiter;

PerHostLimiter::new("eth0", "10mbit")?  // Default rate
    .limit_ip("192.168.1.100".parse()?, "100mbit")?
    .limit_subnet("10.0.0.0/8", "50mbit")?
    .limit_port(80, "500mbit")?
    .apply(&conn)
    .await?;
```

### Implementation Architecture

#### Egress Rate Limiting

```
eth0 -> HTB root (1:) -> HTB class (1:1) -> HTB class (1:10) -> fq_codel (10:)
```

- HTB qdisc at root with default class
- Root class (1:1) for total bandwidth
- Default class (1:10) for rate-limited traffic
- fq_codel leaf qdisc for AQM (Active Queue Management)

#### Ingress Rate Limiting

```
eth0 ingress -> u32 filter -> mirred redirect -> ifb_eth0 -> HTB -> fq_codel
```

- Creates IFB (Intermediate Functional Block) device
- Adds ingress qdisc to main interface
- u32 filter with mirred action redirects traffic to IFB
- HTB + fq_codel on IFB device for actual rate limiting

#### Per-Host Rate Limiting

```
eth0 -> HTB root (1:) -> HTB class (1:1) -> Per-host classes (1:2, 1:3, ...) -> fq_codel
                                         -> Default class (1:N) -> fq_codel
        flower filters classify traffic to appropriate classes
```

- HTB qdisc with multiple child classes
- Each rule gets its own class with rate limit
- Flower filters match IP/subnet/port and classify to classes
- Default class handles unmatched traffic

### API Methods

#### RateLimiter

| Method | Description |
|--------|-------------|
| `new(dev)` | Create limiter for interface |
| `egress(rate)` | Set egress limit (string, e.g., "100mbit") |
| `egress_bps(rate)` | Set egress limit (bytes per second) |
| `ingress(rate)` | Set ingress limit (string) |
| `ingress_bps(rate)` | Set ingress limit (bytes per second) |
| `burst_to(rate)` | Set ceiling rate for bursting |
| `burst_size(size)` | Set burst buffer size |
| `latency(duration)` | Set AQM latency target |
| `apply(conn)` | Apply the rate limits |
| `remove(conn)` | Remove all rate limits |

#### PerHostLimiter

| Method | Description |
|--------|-------------|
| `new(dev, default_rate)` | Create with default rate |
| `limit_ip(ip, rate)` | Add IP-specific limit |
| `limit_subnet(subnet, rate)` | Add subnet limit |
| `limit_src_ip(ip, rate)` | Add source IP limit |
| `limit_src_subnet(subnet, rate)` | Add source subnet limit |
| `limit_port(port, rate)` | Add port-specific limit |
| `limit_port_range(start, end, rate)` | Add port range limit |
| `latency(duration)` | Set AQM latency target |
| `apply(conn)` | Apply the rate limits |
| `remove(conn)` | Remove all rate limits |

#### RateLimit

| Method | Description |
|--------|-------------|
| `new(rate)` | Create with rate in bytes/sec |
| `parse(rate)` | Parse rate string (e.g., "100mbit") |
| `ceil(rate)` | Set ceiling rate |
| `burst(size)` | Set burst size |
| `latency(duration)` | Set latency target |

### HostMatch Types

```rust
pub enum HostMatch {
    Ip(IpAddr),              // Single IP address
    Subnet(IpAddr, u8),      // IP/prefix (e.g., 10.0.0.0/8)
    Port(u16),               // Destination port
    PortRange(u16, u16),     // Port range
    SrcIp(IpAddr),           // Source IP
    SrcSubnet(IpAddr, u8),   // Source subnet
}
```

### Test Coverage

**13 tests** covering:
- RateLimit builder and parsing (4 unit tests)
- RateLimiter builder patterns (2 unit tests)
- PerHostLimiter builder patterns (2 unit tests)
- Egress rate limiting (1 integration test)
- Ingress rate limiting with IFB (1 integration test)
- Bidirectional rate limiting (1 integration test)
- Per-host rate limiting with filters (1 integration test)
- Idempotency verification (1 integration test)

## Design Decisions

### 1. HTB + fq_codel Stack

Chose HTB for hierarchical shaping with fq_codel as leaf for:
- Proper rate limiting with burst support
- Active Queue Management (AQM) for low latency
- Well-tested combination in production environments

### 2. IFB for Ingress

Linux doesn't support direct ingress shaping, so we:
- Create an IFB device per interface
- Redirect ingress traffic to IFB using u32 filter + mirred
- Apply HTB shaping on IFB egress (which is original ingress)

### 3. String Rate Parsing

Reused existing `util::parse::get_rate()` for human-readable rates:
- "100mbit", "1gbit", "10mbps"
- Also support raw bytes-per-second via `*_bps()` methods

### 4. Flower Filters for Per-Host

Used flower filters for per-host classification:
- Better performance than u32 for IP matching
- Supports IPv4 and IPv6
- Native prefix matching support

### 5. Automatic IFB Naming

IFB device names are generated as `ifb_<dev>`:
- Truncated to fit IFNAMSIZ (15 chars + null)
- Predictable naming for cleanup

## Verification

```bash
# Build passes
cargo build -p nlink

# Clippy passes
cargo clippy -p nlink -- -D warnings

# Unit tests pass
cargo test -p nlink ratelimit

# Integration tests compile
cargo test --test integration --no-run
```

## Branch

`feature/plan-013-rate-limit-dsl`

## Commits

```
feat(ratelimit): add high-level rate limiting DSL
```

## Future Enhancements

1. **Ingress Per-Host**: Add per-host limiting for ingress traffic
2. **QoS Classes**: Support multiple QoS tiers (gold/silver/bronze)
3. **Traffic Marking**: Integration with iptables/nftables marks
4. **Statistics**: Add methods to query current usage and drops
5. **Bandwidth Guarantees**: Minimum bandwidth reservations
6. **CAKE Qdisc**: Alternative to HTB+fq_codel for simpler setups
