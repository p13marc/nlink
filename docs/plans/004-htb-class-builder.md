# Plan 004: HTB Class Typed Builder

## Overview

Create a typed builder for HTB classes similar to `NetemConfig` and `HtbQdiscConfig`, providing type-safe class configuration instead of string parameters.

## Motivation

Currently, HTB class configuration requires string parameters:
```rust
conn.add_class("eth0", "1:0", "1:10", "htb", 
    &["rate", "10mbit", "ceil", "100mbit"]).await?;
```

A typed builder would provide:
- Compile-time validation
- IDE autocompletion
- Clearer documentation
- Consistent API with other TC builders

## Design

### API Design

```rust
/// HTB class configuration builder.
#[derive(Debug, Clone)]
pub struct HtbClassConfig {
    /// Guaranteed rate
    rate: u64,
    /// Maximum rate (ceil)
    ceil: Option<u64>,
    /// Burst size in bytes
    burst: Option<u32>,
    /// Ceil burst size in bytes
    cburst: Option<u32>,
    /// Priority (0-7, lower is higher priority)
    prio: Option<u32>,
    /// Quantum for round-robin
    quantum: Option<u32>,
    /// MTU for rate calculations
    mtu: Option<u32>,
    /// Minimum packet unit
    mpu: Option<u16>,
    /// Per-packet overhead
    overhead: Option<u16>,
}

impl HtbClassConfig {
    /// Create a new HTB class with the specified guaranteed rate.
    pub fn new(rate: &str) -> Result<Self>;
    pub fn from_bps(rate: u64) -> Self;
    
    /// Set the maximum rate (ceiling).
    pub fn ceil(self, ceil: &str) -> Result<Self>;
    pub fn ceil_bps(self, ceil: u64) -> Self;
    
    /// Set the burst size.
    pub fn burst(self, burst: &str) -> Result<Self>;
    pub fn burst_bytes(self, burst: u32) -> Self;
    
    /// Set the ceil burst size.
    pub fn cburst(self, cburst: &str) -> Result<Self>;
    pub fn cburst_bytes(self, cburst: u32) -> Self;
    
    /// Set priority (0-7, lower = higher priority).
    pub fn prio(self, prio: u32) -> Self;
    
    /// Set quantum for borrowing.
    pub fn quantum(self, quantum: u32) -> Self;
    
    /// Set MTU for rate calculations.
    pub fn mtu(self, mtu: u32) -> Self;
    
    /// Set minimum packet unit.
    pub fn mpu(self, mpu: u16) -> Self;
    
    /// Set per-packet overhead.
    pub fn overhead(self, overhead: u16) -> Self;
    
    /// Build the configuration.
    pub fn build(self) -> HtbClassBuilt;
}

/// Trait for class configurations.
pub trait ClassConfig {
    fn kind(&self) -> &'static str;
    fn build_options(&self, builder: &mut MessageBuilder) -> Result<()>;
}

impl ClassConfig for HtbClassBuilt { ... }

impl Connection<Route> {
    /// Add a TC class with typed configuration.
    pub async fn add_class_config<C: ClassConfig>(
        &self,
        dev: &str,
        parent: &str,
        classid: &str,
        config: C,
    ) -> Result<()>;
}
```

### Usage Example

```rust
use nlink::netlink::tc::HtbClassConfig;

let conn = Connection::<Route>::new()?;

// First add HTB qdisc
let htb = HtbQdiscConfig::new().default_class(0x30).build();
conn.add_qdisc_full("eth0", "root", "1:", htb).await?;

// Add root class (total bandwidth)
conn.add_class_config("eth0", "1:0", "1:1",
    HtbClassConfig::new("1gbit")?
        .ceil("1gbit")?
        .build()
).await?;

// Add child classes
conn.add_class_config("eth0", "1:1", "1:10",
    HtbClassConfig::new("100mbit")?
        .ceil("500mbit")?
        .prio(1)
        .build()
).await?;

conn.add_class_config("eth0", "1:1", "1:20",
    HtbClassConfig::new("200mbit")?
        .ceil("800mbit")?
        .prio(2)
        .build()
).await?;

conn.add_class_config("eth0", "1:1", "1:30",
    HtbClassConfig::new("50mbit")?
        .ceil("100mbit")?
        .prio(3)
        .build()
).await?;
```

### Implementation Details

The builder constructs `TcHtbOpt` structure and rate tables, similar to the existing `tc/builders/class.rs` but with a cleaner interface.

### File Changes

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/tc.rs` | Add `HtbClassConfig` builder |
| `crates/nlink/src/netlink/connection.rs` | Add `add_class_config` method |
| `crates/nlink/src/netlink/mod.rs` | Export new types |

## Implementation Steps

### Step 1: Add ClassConfig trait

```rust
// In netlink/tc.rs

/// Trait for TC class configurations.
pub trait ClassConfig: Send + Sync {
    /// Get the class type (e.g., "htb", "hfsc").
    fn kind(&self) -> &'static str;
    
    /// Build the TCA_OPTIONS nested attribute.
    fn build_options(&self, builder: &mut MessageBuilder) -> Result<()>;
}
```

### Step 2: Implement HtbClassConfig

```rust
/// HTB class configuration.
#[derive(Debug, Clone)]
pub struct HtbClassConfig {
    rate: u64,
    ceil: Option<u64>,
    burst: Option<u32>,
    cburst: Option<u32>,
    prio: Option<u32>,
    quantum: Option<u32>,
    mtu: u32,
    mpu: u16,
    overhead: u16,
}

impl HtbClassConfig {
    /// Create with rate in bits per second.
    pub fn from_bps(rate: u64) -> Self {
        Self {
            rate,
            ceil: None,
            burst: None,
            cburst: None,
            prio: None,
            quantum: None,
            mtu: 1600,
            mpu: 0,
            overhead: 0,
        }
    }
    
    /// Create with rate string (e.g., "100mbit", "1gbit").
    pub fn new(rate: &str) -> Result<Self> {
        let rate_bps = crate::util::parse::get_rate(rate)?;
        Ok(Self::from_bps(rate_bps))
    }
    
    /// Set ceiling rate.
    pub fn ceil(mut self, ceil: &str) -> Result<Self> {
        self.ceil = Some(crate::util::parse::get_rate(ceil)?);
        Ok(self)
    }
    
    /// Set ceiling rate in bps.
    pub fn ceil_bps(mut self, ceil: u64) -> Self {
        self.ceil = Some(ceil);
        self
    }
    
    /// Set burst size.
    pub fn burst(mut self, burst: &str) -> Result<Self> {
        self.burst = Some(crate::util::parse::get_size(burst)? as u32);
        Ok(self)
    }
    
    /// Set burst size in bytes.
    pub fn burst_bytes(mut self, burst: u32) -> Self {
        self.burst = Some(burst);
        self
    }
    
    /// Set ceil burst size.
    pub fn cburst(mut self, cburst: &str) -> Result<Self> {
        self.cburst = Some(crate::util::parse::get_size(cburst)? as u32);
        Ok(self)
    }
    
    /// Set priority (0-7).
    pub fn prio(mut self, prio: u32) -> Self {
        self.prio = Some(prio.min(7));
        self
    }
    
    /// Set quantum.
    pub fn quantum(mut self, quantum: u32) -> Self {
        self.quantum = Some(quantum);
        self
    }
    
    /// Set MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }
    
    /// Set minimum packet unit.
    pub fn mpu(mut self, mpu: u16) -> Self {
        self.mpu = mpu;
        self
    }
    
    /// Set overhead.
    pub fn overhead(mut self, overhead: u16) -> Self {
        self.overhead = overhead;
        self
    }
    
    /// Build the configuration.
    pub fn build(self) -> HtbClassBuilt {
        HtbClassBuilt(self)
    }
}

/// Built HTB class configuration.
pub struct HtbClassBuilt(HtbClassConfig);

impl ClassConfig for HtbClassBuilt {
    fn kind(&self) -> &'static str {
        "htb"
    }
    
    fn build_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use crate::netlink::types::tc::qdisc::TcRateSpec;
        use crate::netlink::types::tc::qdisc::htb::*;
        
        let cfg = &self.0;
        let rate = cfg.rate;
        let ceil = cfg.ceil.unwrap_or(rate);
        
        // Calculate burst from rate if not specified
        let hz: u64 = 1000;
        let burst = cfg.burst.unwrap_or_else(|| {
            (rate / hz + cfg.mtu as u64) as u32
        });
        let cburst = cfg.cburst.unwrap_or_else(|| {
            (ceil / hz + cfg.mtu as u64) as u32
        });
        
        // Calculate buffer times
        let buffer = if rate > 0 {
            ((burst as u64 * 1_000_000) / rate) as u32
        } else {
            burst
        };
        let cbuffer = if ceil > 0 {
            ((cburst as u64 * 1_000_000) / ceil) as u32
        } else {
            cburst
        };
        
        // Build TcHtbOpt
        let opt = TcHtbOpt {
            rate: TcRateSpec {
                rate: rate.min(u32::MAX as u64) as u32,
                mpu: cfg.mpu,
                overhead: cfg.overhead,
                ..Default::default()
            },
            ceil: TcRateSpec {
                rate: ceil.min(u32::MAX as u64) as u32,
                mpu: cfg.mpu,
                overhead: cfg.overhead,
                ..Default::default()
            },
            buffer,
            cbuffer,
            quantum: cfg.quantum.unwrap_or(0),
            prio: cfg.prio.unwrap_or(0),
            ..Default::default()
        };
        
        // Add 64-bit rates if needed
        if rate >= (1u64 << 32) {
            builder.append_attr(TCA_HTB_RATE64, &rate.to_ne_bytes());
        }
        if ceil >= (1u64 << 32) {
            builder.append_attr(TCA_HTB_CEIL64, &ceil.to_ne_bytes());
        }
        
        builder.append_attr(TCA_HTB_PARMS, opt.as_bytes());
        
        // Rate tables
        let rtab = compute_rate_table(rate, cfg.mtu);
        let ctab = compute_rate_table(ceil, cfg.mtu);
        builder.append_attr(TCA_HTB_RTAB, &rtab);
        builder.append_attr(TCA_HTB_CTAB, &ctab);
        
        Ok(())
    }
}
```

### Step 3: Add Connection method

```rust
impl Connection<Route> {
    /// Add a TC class with typed configuration.
    pub async fn add_class_config<C: ClassConfig>(
        &self,
        dev: &str,
        parent: &str,
        classid: &str,
        config: C,
    ) -> Result<()> {
        let ifindex = crate::util::get_ifindex(dev)
            .map_err(Error::InvalidMessage)?;
        
        let parent_handle = tc_handle::parse(parent)
            .ok_or_else(|| Error::InvalidMessage(format!("invalid parent: {}", parent)))?;
        let class_handle = tc_handle::parse(classid)
            .ok_or_else(|| Error::InvalidMessage(format!("invalid classid: {}", classid)))?;
        
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);
        
        let mut builder = create_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());
        
        let options = builder.nest_start(TcaAttr::Options as u16);
        config.build_options(&mut builder)?;
        builder.nest_end(options);
        
        self.send_ack(builder).await
    }
    
    /// Change a TC class with typed configuration.
    pub async fn change_class_config<C: ClassConfig>(...) -> Result<()>;
    
    /// Replace a TC class with typed configuration.
    pub async fn replace_class_config<C: ClassConfig>(...) -> Result<()>;
}
```

## Testing

```rust
//! Example: HTB class hierarchy

use nlink::netlink::{Connection, Route};
use nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("lo", "root", "1:", htb).await?;
    
    // Root class: 1gbit total
    conn.add_class_config("lo", "1:0", "1:1",
        HtbClassConfig::new("1gbit")?.build()
    ).await?;
    
    // High priority: guaranteed 100mbit, can burst to 500mbit
    conn.add_class_config("lo", "1:1", "1:10",
        HtbClassConfig::new("100mbit")?
            .ceil("500mbit")?
            .prio(1)
            .build()
    ).await?;
    
    // Normal priority: guaranteed 200mbit
    conn.add_class_config("lo", "1:1", "1:20",
        HtbClassConfig::new("200mbit")?
            .ceil("800mbit")?
            .prio(2)
            .build()
    ).await?;
    
    // Best effort: 50mbit guaranteed
    conn.add_class_config("lo", "1:1", "1:30",
        HtbClassConfig::new("50mbit")?
            .prio(3)
            .build()
    ).await?;
    
    // Verify
    let classes = conn.get_classes_for("lo").await?;
    for class in &classes {
        println!("Class {:x}: parent {:x}", class.handle(), class.parent());
    }
    
    // Cleanup
    conn.del_qdisc("lo", "root").await?;
    
    Ok(())
}
```

## Documentation

Update CLAUDE.md with typed HTB class examples.

## Effort Estimate

- Implementation: ~2 hours
- Testing: ~1 hour
- Documentation: ~30 minutes
- **Total: ~3-4 hours**

## Future Work

- Add `HfscClassConfig` for HFSC classes
- Add `DrrClassConfig` for DRR classes
- Add class statistics parsing helpers
