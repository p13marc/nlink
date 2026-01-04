# Report 004: HTB Class Typed Builder

## Summary

Implemented a typed builder pattern for HTB class configuration, providing compile-time validation and IDE autocompletion as an alternative to the existing string-based API.

## Changes

### New Types

#### `ClassConfig` trait (`tc.rs:2449-2463`)
```rust
pub trait ClassConfig: Send + Sync {
    fn kind(&self) -> &'static str;
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;
}
```

Analogous to `QdiscConfig` but for traffic control classes. Enables typed class configurations for classful qdiscs like HTB, HFSC, and DRR.

#### `HtbClassConfig` builder (`tc.rs:2467-2612`)

Type-safe HTB class configuration with:
- `new(rate: &str)` - Parse rate from string (e.g., "100mbit")
- `from_bps(rate: u64)` - Rate in bits per second
- `ceil(ceil: &str)` / `ceil_bps(ceil: u64)` - Maximum rate
- `burst(burst: &str)` / `burst_bytes(burst: u32)` - Burst size
- `cburst(cburst: &str)` / `cburst_bytes(cburst: u32)` - Ceil burst
- `prio(prio: u32)` - Priority (0-7, clamped)
- `quantum(quantum: u32)` - Round-robin quantum
- `mtu(mtu: u32)` - MTU for rate calculations
- `mpu(mpu: u16)` - Minimum packet unit
- `overhead(overhead: u16)` - Per-packet overhead
- `build()` - Returns `HtbClassBuilt`

#### `HtbClassBuilt` (`tc.rs:2614-2739`)

The built configuration that implements `ClassConfig`. Handles:
- Automatic burst calculation from rate if not specified
- 64-bit rate support for rates >= 4 Gbps
- Rate table computation
- Proper kernel structure serialization

### New Connection Methods

Added to `Connection<Route>` (`tc.rs:3505-3677`):
- `add_class_config<C: ClassConfig>(dev, parent, classid, config)`
- `add_class_config_by_index<C: ClassConfig>(ifindex, parent, classid, config)`
- `change_class_config<C: ClassConfig>(...)`
- `change_class_config_by_index<C: ClassConfig>(...)`
- `replace_class_config<C: ClassConfig>(...)`
- `replace_class_config_by_index<C: ClassConfig>(...)`

### Tests Added

5 new tests in `tc.rs`:
- `test_htb_class_config_from_bps` - Basic builder with numeric rates
- `test_htb_class_config_new` - Builder with string rates
- `test_htb_class_config_burst` - All burst/mtu/mpu/overhead options
- `test_htb_class_config_prio_clamp` - Priority clamping to 0-7
- `test_htb_class_config_defaults` - Default value verification

## Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig};

let conn = Connection::<Route>::new()?;

// Add HTB qdisc
let htb = HtbQdiscConfig::new().default_class(0x30).build();
conn.add_qdisc_full("eth0", "root", Some("1:"), htb).await?;

// Add root class
conn.add_class_config("eth0", "1:0", "1:1",
    HtbClassConfig::new("1gbit")?
        .ceil("1gbit")?
        .build()
).await?;

// Add child class with priority
conn.add_class_config("eth0", "1:1", "1:10",
    HtbClassConfig::new("100mbit")?
        .ceil("500mbit")?
        .prio(1)
        .build()
).await?;

// Programmatic rate values
conn.add_class_config("eth0", "1:1", "1:20",
    HtbClassConfig::from_bps(125_000_000)  // 1 Gbps
        .ceil_bps(250_000_000)
        .burst_bytes(64 * 1024)
        .build()
).await?;
```

## Comparison with String-Based API

Before (string-based):
```rust
conn.add_class("eth0", "1:0", "1:10", "htb",
    &["rate", "100mbit", "ceil", "500mbit", "prio", "1"]).await?;
```

After (typed):
```rust
conn.add_class_config("eth0", "1:0", "1:10",
    HtbClassConfig::new("100mbit")?
        .ceil("500mbit")?
        .prio(1)
        .build()
).await?;
```

Benefits:
- Compile-time validation of parameter names
- IDE autocompletion for all options
- Type-safe numeric values (no string parsing at runtime for numeric options)
- Clear documentation of available options
- Consistent with `QdiscConfig` pattern

## Files Modified

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/tc.rs` | +466 lines: ClassConfig trait, HtbClassConfig/HtbClassBuilt, Connection methods, tests |
| `CLAUDE.md` | +71 lines: Typed HTB class configuration examples |

## Future Work

- Add `HfscClassConfig` for HFSC service curve classes
- Add `DrrClassConfig` for DRR quantum classes
- Add `QfqClassConfig` for QFQ weight/lmax classes
