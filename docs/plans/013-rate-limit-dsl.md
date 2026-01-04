# Plan 013: Rate Limiting DSL

## Overview

Add a high-level rate limiting API that abstracts away TC complexity for common bandwidth management use cases.

## Motivation

Current TC API requires understanding:
- Qdisc types (HTB, TBF, etc.)
- Class hierarchies
- Filter matching
- Handle numbering

A simpler API would make rate limiting accessible for common cases.

## Design

### API Design

```rust
/// High-level rate limiter.
pub struct RateLimiter {
    dev: String,
    ingress: Option<RateLimit>,
    egress: Option<RateLimit>,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Guaranteed rate
    rate: u64,
    /// Maximum burst rate
    ceil: Option<u64>,
    /// Burst size
    burst: Option<u32>,
    /// Latency target for AQM
    latency: Option<Duration>,
}

impl RateLimiter {
    /// Create a rate limiter for an interface.
    pub fn new(dev: &str) -> Self;
    
    /// Set egress (upload) rate limit.
    pub fn egress(self, rate: &str) -> Result<Self>;
    pub fn egress_bps(self, rate: u64) -> Self;
    
    /// Set ingress (download) rate limit.
    pub fn ingress(self, rate: &str) -> Result<Self>;
    pub fn ingress_bps(self, rate: u64) -> Self;
    
    /// Allow bursting to higher rate.
    pub fn burst_to(self, ceil: &str) -> Result<Self>;
    
    /// Set burst buffer size.
    pub fn burst_size(self, size: &str) -> Result<Self>;
    
    /// Set latency target (for AQM).
    pub fn latency(self, latency: Duration) -> Self;
    
    /// Apply the rate limits.
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()>;
    
    /// Remove rate limits.
    pub async fn remove(&self, conn: &Connection<Route>) -> Result<()>;
}

/// Per-IP or per-subnet rate limiting.
pub struct PerHostLimiter {
    dev: String,
    default_rate: u64,
    rules: Vec<HostRule>,
}

#[derive(Debug, Clone)]
pub struct HostRule {
    match_: HostMatch,
    rate: u64,
    ceil: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum HostMatch {
    Ip(IpAddr),
    Subnet(IpAddr, u8),
    Port(u16),
    PortRange(u16, u16),
}

impl PerHostLimiter {
    pub fn new(dev: &str, default_rate: &str) -> Result<Self>;
    
    /// Add rate limit for specific IP.
    pub fn limit_ip(self, ip: IpAddr, rate: &str) -> Result<Self>;
    
    /// Add rate limit for subnet.
    pub fn limit_subnet(self, subnet: &str, rate: &str) -> Result<Self>;
    
    /// Add rate limit for port.
    pub fn limit_port(self, port: u16, rate: &str) -> Result<Self>;
    
    /// Apply configuration.
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()>;
}
```

### Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::ratelimit::{RateLimiter, PerHostLimiter};
use std::time::Duration;

let conn = Connection::<Route>::new()?;

// Simple rate limiting
RateLimiter::new("eth0")
    .egress("100mbit")?
    .ingress("1gbit")?
    .burst_to("150mbit")?
    .latency(Duration::from_millis(20))
    .apply(&conn)
    .await?;

// Per-host limiting
PerHostLimiter::new("eth0", "10mbit")?
    .limit_ip("192.168.1.100".parse()?, "100mbit")?
    .limit_subnet("10.0.0.0/8", "50mbit")?
    .limit_port(80, "500mbit")?
    .apply(&conn)
    .await?;

// Remove limits
RateLimiter::new("eth0")
    .remove(&conn)
    .await?;
```

### Implementation Details

Under the hood:
- Egress: Uses HTB qdisc with single class
- Ingress: Uses IFB device + redirect + HTB
- Per-host: Uses HTB with flower filters
- AQM: Attaches fq_codel as leaf qdisc

```
Egress:
  eth0 -> HTB root -> HTB class (rate limited) -> fq_codel

Ingress:
  eth0 ingress -> mirred redirect -> ifb0 -> HTB -> fq_codel
```

## Implementation Steps

1. Create `ratelimit` module
2. Implement simple egress limiting
3. Implement ingress limiting with IFB
4. Add per-host limiting with filters
5. Add AQM integration

## Effort Estimate

- Simple rate limiter: ~4 hours
- Ingress with IFB: ~3 hours
- Per-host limiting: ~4 hours
- AQM integration: ~2 hours
- **Total: ~13 hours**
