# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nlink is a Rust library for Linux network configuration via netlink. The primary goal is to provide a well-designed Rust crate for programmatic network management. The binaries (`ip`, `tc`, `ss`) serve as proof-of-concept demonstrations.

**Key design decisions:**
- Custom netlink implementation - no dependency on rtnetlink/netlink-packet-* crates
- Async/tokio native using AsyncFd
- Library-first architecture - binaries are thin wrappers
- Single publishable crate with feature flags
- Rust edition 2024

## Build Commands

```bash
cargo build                    # Build all crates and binaries
cargo build -p nlink           # Build the library
cargo build -p nlink-ip        # Build ip binary
cargo test                     # Run all tests
cargo test -p nlink            # Test the library
```

## Architecture

### Library Crate

**nlink** (`crates/nlink/`) - Single publishable crate with feature-gated modules:

```
crates/nlink/src/
  lib.rs              # Main entry point, re-exports
  netlink/            # Core netlink (always available)
    connection.rs     # High-level request/response/dump handling
    socket.rs         # Low-level async socket using netlink-sys + tokio AsyncFd
    builder.rs        # Message construction with MessageBuilder
    message.rs        # Netlink header parsing, MessageIter
    attr.rs           # Attribute (TLV) parsing with AttrIter
    events.rs         # High-level event monitoring (EventStream, NetworkEvent)
    namespace.rs      # Network namespace utilities
    stats.rs          # Statistics tracking (StatsSnapshot, StatsTracker)
    tc.rs             # TC typed builders (NetemConfig, FqCodelConfig, etc.)
    tc_options.rs     # TC options parsing
    messages/         # Strongly-typed message structs
    types/            # RTNetlink message structures (link, addr, route, neigh, rule, tc)
  util/               # Shared utilities (always available)
    addr.rs           # IP/MAC address parsing and formatting
    ifname.rs         # Interface name/index conversion
    names.rs          # Protocol/scope/table name resolution
    parse.rs          # Rate/size/time string parsing
  sockdiag/           # Socket diagnostics (feature: sockdiag)
  tuntap/             # TUN/TAP device management (feature: tuntap)
  tc/                 # Traffic control utilities (feature: tc)
  output/             # Output formatting (feature: output)
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `sockdiag` | Socket diagnostics via NETLINK_SOCK_DIAG |
| `tuntap` | TUN/TAP device management |
| `tc` | Traffic control utilities (qdisc builders, handle parsing) |
| `output` | JSON/text output formatting |
| `full` | All features enabled |

### Binaries

- `bins/ip/` - Network configuration (depends on `nlink` with `output` feature)
- `bins/tc/` - Traffic control (depends on `nlink` with `tc`, `output` features)
- `bins/ss/` - Socket statistics (depends on `nlink` with `sockdiag`, `output` features)

## Key Patterns

**High-level queries (preferred for library use):**
```rust
use nlink::netlink::{Connection, Protocol};

let conn = Connection::new(Protocol::Route)?;

// Query interfaces
let links = conn.get_links().await?;
let eth0 = conn.get_link_by_name("eth0").await?;

// Query addresses
let addrs = conn.get_addresses().await?;
let eth0_addrs = conn.get_addresses_for("eth0").await?;

// Query routes
let routes = conn.get_routes().await?;

// Query TC
let qdiscs = conn.get_qdiscs().await?;
let classes = conn.get_classes_for("eth0").await?;
```

**Link state management:**
```rust
use nlink::netlink::{Connection, Protocol};

let conn = Connection::new(Protocol::Route)?;

// Bring interface up/down
conn.set_link_up("eth0").await?;
conn.set_link_down("eth0").await?;

// Set MTU
conn.set_link_mtu("eth0", 9000).await?;

// Delete a virtual interface
conn.del_link("veth0").await?;
```

**Network namespace operations:**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::namespace;

// Connect to a named namespace (created via `ip netns add myns`)
let conn = namespace::connection_for("myns")?;
let links = conn.get_links().await?;

// Connect to a container's namespace by PID
let conn = namespace::connection_for_pid(container_pid)?;

// Or use a path directly
let conn = Connection::new_in_namespace_path(
    Protocol::Route,
    "/proc/1234/ns/net"
)?;

// List available namespaces
for ns in namespace::list()? {
    println!("Namespace: {}", ns);
}
```

**Parsing TC options:**
```rust
use nlink::netlink::tc_options::{parse_qdisc_options, QdiscOptions};

for qdisc in &qdiscs {
    if let Some(opts) = parse_qdisc_options(qdisc) {
        match opts {
            QdiscOptions::FqCodel(fq) => println!("target={}us", fq.target_us),
            QdiscOptions::Htb(htb) => println!("default={:x}", htb.default_class),
            _ => {}
        }
    }
}
```

**Reading netem configuration (detecting existing TC settings):**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::tc_options::QdiscOptions;

let conn = Connection::new(Protocol::Route)?;
let qdiscs = conn.get_qdiscs_for("eth0").await?;

for qdisc in &qdiscs {
    // Option 1: Use convenience method directly on TcMessage
    if let Some(netem) = qdisc.netem_options() {
        println!("delay={}us, jitter={}us", netem.delay_us, netem.jitter_us);
        println!("loss={}%, correlation={}%", netem.loss_percent, netem.loss_corr);
        println!("duplicate={}%", netem.duplicate_percent);
        println!("reorder={}%, gap={}", netem.reorder_percent, netem.gap);
        println!("corrupt={}%", netem.corrupt_percent);
        if netem.rate > 0 {
            println!("rate={} bytes/sec", netem.rate);
        }
    }

    // Option 2: Use parsed_options() for all qdisc types
    if let Some(QdiscOptions::Netem(netem)) = qdisc.parsed_options() {
        // Same fields available
    }
}
```

**Statistics tracking:**
```rust
use nlink::netlink::stats::{StatsSnapshot, StatsTracker};

let mut tracker = StatsTracker::new();
loop {
    let links = conn.get_links().await?;
    let snapshot = StatsSnapshot::from_links(&links);
    if let Some(rates) = tracker.update(snapshot) {
        for (idx, r) in &rates.links {
            println!("idx {}: {:.2} Mbps", idx, r.total_bps() / 1_000_000.0);
        }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
}
```

**Monitoring events (high-level API - preferred):**
```rust
use nlink::netlink::events::{EventStream, NetworkEvent};

let mut stream = EventStream::builder()
    .links(true)
    .addresses(true)
    .tc(true)
    .build()?;

while let Some(event) = stream.next().await? {
    match event {
        NetworkEvent::NewLink(link) => println!("Link: {}", link.name.unwrap_or_default()),
        NetworkEvent::NewAddress(addr) => println!("Addr: {:?}", addr.address),
        NetworkEvent::NewQdisc(tc) => println!("Qdisc: {}", tc.kind().unwrap_or("?")),
        _ => {}
    }
}
```

**Namespace-aware event monitoring:**
```rust
use nlink::netlink::events::{EventStream, NetworkEvent};

// Monitor events in a named namespace
let mut stream = EventStream::builder()
    .namespace("myns")
    .links(true)
    .tc(true)
    .build()?;

// Or by PID (e.g., container process)
let mut stream = EventStream::builder()
    .namespace_pid(container_pid)
    .links(true)
    .build()?;

// Or by path
let mut stream = EventStream::builder()
    .namespace_path("/proc/1234/ns/net")
    .all()
    .build()?;
```

**Namespace-aware TC operations (using ifindex):**
```rust
use nlink::netlink::{namespace, tc::NetemConfig};
use std::time::Duration;

// For namespace operations, use *_by_index methods to avoid
// reading /sys/class/net/ from the host namespace
let conn = namespace::connection_for("myns")?;
let link = conn.get_link_by_name("eth0").await?;

let netem = NetemConfig::new()
    .delay(Duration::from_millis(100))
    .loss(1.0)
    .build();

// Use ifindex instead of device name
conn.add_qdisc_by_index(link.ifindex(), netem).await?;

// All TC methods have *_by_index variants:
// - add_qdisc_by_index / add_qdisc_by_index_full
// - del_qdisc_by_index / del_qdisc_by_index_full
// - replace_qdisc_by_index / replace_qdisc_by_index_full
// - change_qdisc_by_index / change_qdisc_by_index_full
```

**Building requests (low-level):**
```rust
use nlink::netlink::{MessageBuilder, Connection};
use nlink::netlink::message::NlMsgType;
use nlink::netlink::types::link::IfInfoMsg;

let mut builder = dump_request(NlMsgType::RTM_GETLINK);
builder.append(&IfInfoMsg::new());
let responses = conn.dump(builder).await?;
```

**Adding TC qdisc with options:**
```rust
use nlink::netlink::types::tc::qdisc::htb::*;
use nlink::netlink::types::tc::{TcMsg, TcaAttr, tc_handle};

let tcmsg = TcMsg::new()
    .with_ifindex(ifindex)
    .with_parent(tc_handle::ROOT)
    .with_handle(tc_handle::make(1, 0));

let mut builder = create_request(NlMsgType::RTM_NEWQDISC);
builder.append(&tcmsg);
builder.append_attr_str(TcaAttr::Kind as u16, "htb");

let options_token = builder.nest_start(TcaAttr::Options as u16);
let glob = TcHtbGlob::new().with_default(0x10);
builder.append_attr(TCA_HTB_INIT, glob.as_bytes());
builder.nest_end(options_token);

conn.request_ack(builder).await?;
```

## Netlink Message Flow

1. Create `Connection` for `Protocol::Route`
2. Build request with `MessageBuilder::new(msg_type, flags)`
3. Append message struct (e.g., `IfInfoMsg`) with `builder.append(&msg)`
4. Add attributes with `builder.append_attr*()` methods
5. For nested attributes: `nest_start()` / `nest_end()`
6. Send via `conn.dump()` (for GET) or `conn.request_ack()` (for ADD/DEL)
7. Parse responses with `MessageIter` and `AttrIter`

## Publishing

The `nlink` crate is the only publishable crate. All binaries have `publish = false`.

```bash
cargo publish -p nlink
```
