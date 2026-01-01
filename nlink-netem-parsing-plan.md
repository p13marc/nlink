# nlink Crate Improvement: Netem Config Parsing

## Problem Statement

When the tcgui backend starts, it needs to detect existing TC configurations on interfaces so the frontend can display the correct checkbox states. Currently, this detection fails because the nlink crate doesn't expose netem parameters when reading qdiscs.

### Current Behavior

The nlink crate's `get_qdiscs_for()` returns qdisc objects with only basic info:

```rust
pub trait Qdisc {
    fn kind(&self) -> Option<&str>;    // "netem", "fq_codel", etc.
    fn parent(&self) -> u32;           // Parent handle
    fn handle(&self) -> u32;           // Qdisc handle
}
```

### Missing Information

Netem-specific parameters are not exposed:
- Loss percentage and correlation
- Delay (base, jitter, correlation)
- Duplicate percentage and correlation
- Reorder percentage, correlation, and gap
- Corrupt percentage and correlation
- Rate limit

### Impact

When backend restarts with an existing netem qdisc (e.g., `loss 1%` on docker0):
1. `check_existing_qdisc()` returns `"qdisc netem root"` (no parameters)
2. `parse_tc_parameters()` finds no loss/delay/etc values
3. Frontend receives config with `loss: 0.0`
4. LSS checkbox stays unchecked despite TC being active

## Proposed Solution

### Option 1: Enhance nlink crate (Recommended)

Add netem config parsing to the nlink crate.

#### 1.1 Parse TCA_OPTIONS attribute

When reading qdiscs via netlink, the kernel returns `TCA_OPTIONS` containing netem parameters in a `tc_netem_qopt` structure:

```c
struct tc_netem_qopt {
    __u32 latency;      /* added delay (us) */
    __u32 limit;        /* fifo limit (packets) */
    __u32 loss;         /* random packet loss (0=none ~0=100%) */
    __u32 gap;          /* re-ordering gap (0 for none) */
    __u32 duplicate;    /* random packet dup (0=none ~0=100%) */
    __u32 jitter;       /* random jitter in latency (us) */
};
```

Additional parameters come in nested attributes:
- `TCA_NETEM_CORR` - correlation values
- `TCA_NETEM_CORRUPT` - corruption settings
- `TCA_NETEM_REORDER` - reorder settings
- `TCA_NETEM_RATE` - rate limiting

#### 1.2 Add method to Qdisc trait or struct

```rust
impl Qdisc {
    /// Get netem configuration if this is a netem qdisc
    pub fn netem_config(&self) -> Option<ParsedNetemConfig> {
        if self.kind() != Some("netem") {
            return None;
        }
        // Parse TCA_OPTIONS into config
        Some(ParsedNetemConfig {
            delay_us: self.parse_delay(),
            jitter_us: self.parse_jitter(),
            loss_percent: self.parse_loss(),
            duplicate_percent: self.parse_duplicate(),
            reorder_percent: self.parse_reorder(),
            corrupt_percent: self.parse_corrupt(),
            rate_bytes_per_sec: self.parse_rate(),
            // ... correlations
        })
    }
}
```

#### 1.3 New struct for parsed netem config

```rust
/// Parsed netem configuration from an existing qdisc
#[derive(Debug, Clone, Default)]
pub struct ParsedNetemConfig {
    pub delay_us: u32,
    pub jitter_us: u32,
    pub delay_correlation: f64,
    pub loss_percent: f64,
    pub loss_correlation: f64,
    pub duplicate_percent: f64,
    pub duplicate_correlation: f64,
    pub reorder_percent: f64,
    pub reorder_correlation: f64,
    pub gap: u32,
    pub corrupt_percent: f64,
    pub corrupt_correlation: f64,
    pub rate_bytes_per_sec: Option<u64>,
    pub limit: u32,
}
```

### Option 2: Hybrid approach (Quick fix)

Use the `tc` command for reading existing config, keep nlink for applying.

```rust
pub async fn check_existing_qdisc(&self, namespace: &str, interface: &str) -> Result<String> {
    // Run: tc qdisc show dev <interface>
    // Returns full output like: "qdisc netem 8006: root refcnt 2 limit 1000 loss 1%"
}
```

#### Pros
- Works immediately
- No changes to nlink needed

#### Cons  
- Requires parsing text output (fragile)
- Spawns external process
- Inconsistent: nlink for write, tc command for read

## Recommendation

**Option 1 (Enhance nlink)** is the better long-term solution because:
1. Consistent use of netlink for all TC operations
2. No text parsing required
3. More efficient (no process spawning)
4. Type-safe access to parameters

However, **Option 2** can be used as a temporary workaround while nlink improvements are developed.

## Implementation Steps for Option 1

1. [x] Add `TCA_NETEM_*` attribute constants to nlink (already existed in `types/tc.rs`)
2. [x] Implement `tc_netem_qopt` structure parsing (already existed in `tc_options.rs`)
3. [x] Parse nested attributes (CORR, CORRUPT, REORDER, RATE) (already existed)
4. [x] Add `ParsedNetemConfig` struct (exists as `NetemOptions` in `tc_options.rs`)
5. [x] Add `netem_config()` method to Qdisc (added `netem_options()` and `parsed_options()` to `TcMessage`)
6. [ ] Update tcgui-backend to use new API
7. [x] Add tests for parsing various netem configurations

## Summary of Changes Made

The nlink crate already had full netem parsing support. The following improvements were made:

### New Convenience Methods on `TcMessage`

Added to `crates/nlink/src/netlink/messages/tc.rs`:

```rust
// Get parsed qdisc options (any type)
pub fn parsed_options(&self) -> Option<QdiscOptions>

// Get netem options specifically (convenience method)
pub fn netem_options(&self) -> Option<NetemOptions>
```

### Usage Example for tcgui-backend

```rust
use nlink::netlink::{Connection, Protocol};

let conn = Connection::new(Protocol::Route)?;
let qdiscs = conn.get_qdiscs_for("docker0").await?;

for qdisc in &qdiscs {
    if let Some(netem) = qdisc.netem_options() {
        // Now you can access all netem parameters:
        // netem.loss_percent, netem.delay_us, netem.jitter_us, etc.
        println!("loss={}%", netem.loss_percent);
    }
}
```

### New Tests Added

- `test_netem_defaults`
- `test_netem_parse_basic`
- `test_netem_parse_with_correlation`
- `test_netem_parse_with_reorder`
- `test_netem_parse_with_corrupt`
- `test_netem_parse_with_rate`
- `test_netem_parse_with_rate64`
- `test_netem_parse_multiple_attrs`
- `test_netem_prob_conversion_roundtrip`

## References

- Linux kernel netem source: `net/sched/sch_netem.c`
- Netlink TC attributes: `include/uapi/linux/pkt_sched.h`
- tc-netem man page: `man tc-netem`
