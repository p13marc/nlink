# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rip is a Rust library for Linux network configuration via netlink. The primary goal is to provide well-designed Rust crates for programmatic network management. The binaries (`ip`, `tc`) serve as proof-of-concept demonstrations.

**Key design decisions:**
- Custom netlink implementation - no dependency on rtnetlink/netlink-packet-* crates
- Async/tokio native using AsyncFd
- Library-first architecture - binaries are thin wrappers
- Rust edition 2024

## Build Commands

```bash
cargo build                    # Build all crates and binaries
cargo build -p rip-netlink     # Build specific crate
cargo test                     # Run all tests
cargo test -p rip-netlink      # Test specific crate
```

## Architecture

### Core Libraries (the main deliverables)

**rip-netlink** (`crates/rip-netlink/`) - Async netlink protocol implementation:
- `socket.rs` - Low-level async socket using `netlink-sys` + tokio `AsyncFd`
- `connection.rs` - High-level request/response/dump handling
- `builder.rs` - Message construction with `MessageBuilder`, supports nested attributes
- `message.rs` - Netlink header parsing, `MessageIter` for multi-message responses
- `attr.rs` - Attribute (TLV) parsing with `AttrIter`, type extraction helpers in `get` module
- `types/` - RTNetlink message structures:
  - `link.rs` - Interface info (IFLA_* attributes, IFF_* flags)
  - `addr.rs` - Address info (IFA_* attributes)
  - `route.rs` - Routing (RTA_* attributes)
  - `neigh.rs` - Neighbor/ARP (NDA_* attributes)
  - `tc.rs` - Traffic control (TCA_* attributes, qdisc/filter/action constants)

**rip-lib** (`crates/rip-lib/`) - Shared utilities:
- `addr.rs` - IP/MAC address parsing and formatting
- `ifname.rs` - Interface name/index conversion via ioctl
- `names.rs` - Protocol/scope/table name resolution
- `parse.rs` - Rate/size/time string parsing (e.g., "1mbit", "100ms")

**rip-output** (`crates/rip-output/`) - Output formatting for text and JSON

### Proof-of-Concept Binaries

- `bins/ip/` - Network configuration (`ip link`, `ip addr`, `ip route`, `ip neigh`)
- `bins/tc/` - Traffic control (`tc qdisc`, `tc class`, `tc filter`)

## Netlink Message Flow

1. Create `Connection` for `Protocol::Route`
2. Build request with `MessageBuilder::new(msg_type, flags)`
3. Append message struct (e.g., `IfInfoMsg`) with `builder.append(&msg)`
4. Add attributes with `builder.append_attr*()` methods
5. For nested attributes: `nest_start()` / `nest_end()`
6. Send via `conn.dump()` (for GET) or `conn.request_ack()` (for ADD/DEL)
7. Parse responses with `MessageIter` and `AttrIter`

## Key Patterns

**Parsing netlink responses:**
```rust
for (attr_type, attr_data) in AttrIter::new(attrs_data) {
    match IflaAttr::from(attr_type) {
        IflaAttr::Ifname => name = get::string(attr_data)?,
        IflaAttr::Mtu => mtu = get::u32_ne(attr_data)?,
        // ...
    }
}
```

**Building requests:**
```rust
let mut builder = dump_request(NlMsgType::RTM_GETLINK);
builder.append(&IfInfoMsg::new());
let responses = conn.dump(builder).await?;
```
