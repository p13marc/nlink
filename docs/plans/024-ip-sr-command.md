# Plan 024: Add `ip sr` Command (Segment Routing)

## Overview

Add Segment Routing (SRv6) management to the `ip` binary, exposing the SRv6 API from Plan 007.

## Current State

- Library: Full SRv6 support in `netlink/srv6.rs` (1,062 lines)
- Binary: No sr command exists
- iproute2 equivalent: `ip sr`

## Target Commands

```bash
# Show SRv6 local SIDs (End, End.X, End.DT4, etc.)
ip sr tunsrc show
ip sr tunsrc set 2001:db8::1

# Manage SRv6 localsid table
ip -6 route show type seg6local
ip -6 route add 2001:db8:1::100 encap seg6local action End dev eth0
ip -6 route add 2001:db8:1::101 encap seg6local action End.X nh6 fe80::1 dev eth0
ip -6 route add 2001:db8:1::102 encap seg6local action End.DT4 table 100
ip -6 route add 2001:db8:1::103 encap seg6local action End.DT6 table 100
ip -6 route add 2001:db8:1::104 encap seg6local action End.B6.Encaps srh segs 2001:db8:2::1,2001:db8:3::1

# Add route with SRv6 encapsulation
ip route add 10.0.0.0/8 encap seg6 mode encap segs 2001:db8:1::1,2001:db8:2::1 dev eth0
ip route add 10.0.0.0/8 encap seg6 mode inline segs 2001:db8:1::1 dev eth0

# Delete SRv6 routes
ip -6 route del 2001:db8:1::100
```

## Implementation

### Files to Create/Modify

1. **Create `bins/ip/src/sr.rs`**
   - `SrArgs` struct with clap derive
   - `SrCommand` enum (Tunsrc)
   - `run_sr()` async function

2. **Modify `bins/ip/src/route.rs`**
   - Add `--encap seg6` and `--encap seg6local` options
   - Parse SRv6 encapsulation parameters

3. **Modify `bins/ip/src/main.rs`**
   - Add `sr` to Command enum

### Command Structure

```rust
// sr.rs
#[derive(Parser)]
pub struct SrArgs {
    #[command(subcommand)]
    pub command: SrCommand,
}

#[derive(Subcommand)]
pub enum SrCommand {
    /// Manage tunnel source address
    Tunsrc {
        #[command(subcommand)]
        command: TunsrcCommand,
    },
}

#[derive(Subcommand)]
pub enum TunsrcCommand {
    /// Show tunnel source
    Show,
    /// Set tunnel source
    Set {
        /// Source IPv6 address
        address: Ipv6Addr,
    },
}
```

### Route Encapsulation Extension

```rust
// In route.rs, extend RouteAddArgs

#[derive(Args)]
pub struct RouteAddArgs {
    // ... existing fields ...
    
    /// Encapsulation type (seg6, seg6local, mpls)
    #[arg(long)]
    encap: Option<String>,
    
    /// SRv6 mode (encap, inline)
    #[arg(long)]
    mode: Option<String>,
    
    /// SRv6 segments (comma-separated)
    #[arg(long)]
    segs: Option<String>,
    
    /// SRv6 action (End, End.X, End.DT4, End.DT6, End.B6.Encaps)
    #[arg(long)]
    action: Option<String>,
    
    /// Next hop for End.X
    #[arg(long)]
    nh6: Option<Ipv6Addr>,
    
    /// SRH segments for End.B6.Encaps
    #[arg(long)]
    srh: Option<String>,
    
    /// Table for End.DT4/End.DT6
    #[arg(long)]
    table: Option<u32>,
}

// Parse SRv6 encapsulation
fn parse_srv6_encap(args: &RouteAddArgs) -> Option<Srv6Encap> {
    if args.encap.as_deref() != Some("seg6") {
        return None;
    }
    
    let segs: Vec<Ipv6Addr> = args.segs.as_ref()?
        .split(',')
        .map(|s| s.parse())
        .collect::<Result<_, _>>()
        .ok()?;
    
    let mode = match args.mode.as_deref() {
        Some("inline") => Srv6Mode::Inline,
        _ => Srv6Mode::Encap,
    };
    
    Some(Srv6Encap::new(mode).segments(&segs))
}

// Parse SRv6 local SID action
fn parse_srv6_local(args: &RouteAddArgs) -> Option<Srv6LocalBuilder> {
    if args.encap.as_deref() != Some("seg6local") {
        return None;
    }
    
    let sid: Ipv6Addr = args.destination.parse().ok()?;
    
    match args.action.as_deref()? {
        "End" => Some(Srv6LocalBuilder::end(sid)),
        "End.X" => {
            let nh = args.nh6?;
            Some(Srv6LocalBuilder::end_x(sid, nh))
        }
        "End.DT4" => {
            let table = args.table.unwrap_or(254);
            Some(Srv6LocalBuilder::end_dt4(sid, table))
        }
        "End.DT6" => {
            let table = args.table.unwrap_or(254);
            Some(Srv6LocalBuilder::end_dt6(sid, table))
        }
        "End.B6.Encaps" => {
            let segs: Vec<Ipv6Addr> = args.srh.as_ref()?
                .split(',')
                .map(|s| s.parse())
                .collect::<Result<_, _>>()
                .ok()?;
            Some(Srv6LocalBuilder::end_b6_encaps(sid, &segs))
        }
        _ => None,
    }
}
```

## Output Format

### SRv6 Route Text Output

```
2001:db8:1::100 encap seg6local action End dev eth0
2001:db8:1::101 encap seg6local action End.X nh6 fe80::1 dev eth0
2001:db8:1::102 encap seg6local action End.DT4 table 100
10.0.0.0/8 encap seg6 mode encap segs 2001:db8:1::1,2001:db8:2::1 dev eth0
```

### Tunsrc Output

```
tunsrc addr 2001:db8::1
```

## Testing

```bash
# Setup test environment
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo ip -6 addr add 2001:db8::1/64 dev dummy0

# Add SRv6 local SID
sudo ./target/release/ip -6 route add 2001:db8:1::100 \
    encap seg6local action End dev dummy0

# Add route with SRv6 encapsulation
sudo ./target/release/ip route add 10.0.0.0/8 \
    encap seg6 mode encap segs 2001:db8:1::1 dev dummy0

# Show SRv6 routes
./target/release/ip -6 route show type seg6local

# Cleanup
sudo ip link del dummy0
```

## Estimated Effort

- sr.rs (tunsrc): 1-2 hours
- Route encapsulation extension: 3-4 hours
- Output formatting: 1-2 hours
- Testing: 1-2 hours
- Total: 1 day

## Dependencies

- `nlink::netlink::srv6::{Srv6Encap, Srv6LocalBuilder, Srv6Mode}`
- `nlink::netlink::route::{Ipv4Route, Ipv6Route}`

## Notes

- SRv6 requires kernel with `CONFIG_IPV6_SEG6_LWTUNNEL=y`
- tunsrc is used for End.B6 behavior (source address for encapsulated packets)
- The full `ip sr` command in iproute2 also supports HMAC, which we don't implement
