# Strongly-Typed Library API Design for nlink

## Executive Summary

The current nlink crate provides a working low-level netlink implementation, but the library API requires significant boilerplate from consumers. Each message type requires 40-60 lines of hand-written parsing code with manual type conversions and no compile-time safety guarantees.

This document proposes a strongly-typed API layer using parser combinators (winnow) and derive macros to provide:
- Zero-copy parsing with compile-time type safety
- Type-aware attribute iteration
- Validated message construction
- Automatic handling of nested attributes

---

## 1. Current State Analysis

### 1.1 Parsing Pattern (Repeated in Every Binary)

```rust
// From bins/ip/src/commands/address.rs - ~50 lines per message type
fn parse_addr_message(data: &[u8]) -> Result<Option<AddrInfo>> {
    let payload = &data[NLMSG_HDRLEN..];
    let ifaddr = IfAddrMsg::from_bytes(payload)?;
    let attrs_data = &payload[IfAddrMsg::SIZE..];

    let mut address = String::new();
    let mut local = None;
    let mut label = None;

    // Manual iteration with raw u16 types
    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match IfaAttr::from(attr_type) {
            IfaAttr::Address => {
                // Must know correct extraction function
                address = format_addr_bytes(attr_data, ifaddr.ifa_family)?;
            }
            IfaAttr::Local => {
                local = format_addr_bytes(attr_data, ifaddr.ifa_family);
            }
            IfaAttr::Label => {
                // Different extraction for strings
                label = Some(get::string(attr_data)?.to_string());
            }
            _ => {}
        }
    }
    // ... construct result
}
```

### 1.2 Problems

| Problem | Impact |
|---------|--------|
| **No type safety** | Can append attribute 999 without error |
| **Manual extraction** | Must know `get::u32()` vs `get::string()` for each attr |
| **Boilerplate** | ~50 lines repeated for each message type (addr, route, link, neigh, rule) |
| **Silent failures** | `unwrap_or_default()` hides parsing errors |
| **No nested type info** | Nested attributes require manual re-parsing |
| **No validation** | Can construct invalid messages missing required fields |

### 1.3 Code Duplication

The same parsing pattern exists in:
- `bins/ip/src/commands/address.rs` (lines 352-395)
- `bins/ip/src/commands/route.rs` (lines 472-513)
- `bins/ip/src/commands/link.rs` (lines 319-385)
- `bins/ip/src/commands/neighbor.rs` (lines ~300-350)
- `bins/ip/src/commands/rule.rs` (lines ~250-300)
- `bins/tc/src/commands/qdisc.rs` (lines ~400-500)

Each is nearly identical structure with different attribute enums.

---

## 2. Proposed Architecture

### 2.1 Layer Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    User Application                      │
├─────────────────────────────────────────────────────────┤
│              nlink (High-Level API)                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │ AddressMsg  │  │  RouteMsg   │  │    LinkMsg      │  │
│  │ ::parse()   │  │ ::parse()   │  │   ::parse()     │  │
│  │ ::build()   │  │ ::build()   │  │   ::build()     │  │
│  └─────────────┘  └─────────────┘  └─────────────────┘  │
├─────────────────────────────────────────────────────────┤
│                   Derive Macros Layer                    │
│  #[derive(NetlinkMessage)]  #[derive(NetlinkAttr)]      │
├─────────────────────────────────────────────────────────┤
│                   Parser Combinators                     │
│            winnow-based binary parsing                   │
├─────────────────────────────────────────────────────────┤
│              nlink (Low-Level API)                 │
│  NetlinkSocket, Connection, MessageBuilder, AttrIter    │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Core Traits

```rust
/// Trait for types that can be parsed from netlink wire format
pub trait FromNetlink: Sized {
    /// Parse from a byte slice, returning the parsed value and remaining bytes
    fn parse(input: &[u8]) -> winnow::PResult<Self>;
    
    /// Parse from a complete message (convenience method)
    fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::parse.parse(data)
            .map_err(|e| Error::Parse(e.to_string()))
    }
}

/// Trait for types that can be serialized to netlink wire format
pub trait ToNetlink {
    /// Calculate the serialized size (for pre-allocation)
    fn netlink_len(&self) -> usize;
    
    /// Serialize into a MessageBuilder
    fn write_to(&self, builder: &mut MessageBuilder) -> Result<()>;
    
    /// Convenience method to build a complete message
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut builder = MessageBuilder::with_capacity(self.netlink_len());
        self.write_to(&mut builder)?;
        Ok(builder.finish())
    }
}

/// Trait for netlink attribute enums with type information
pub trait NetlinkAttrType: From<u16> + Into<u16> + Copy {
    /// The Rust type this attribute contains
    type Value;
    
    /// Parse the attribute value from bytes
    fn parse_value(&self, data: &[u8]) -> Result<Self::Value>;
}
```

---

## 3. Parser Combinator Approach (winnow)

### 3.1 Why winnow Over nom?

| Feature | winnow | nom |
|---------|--------|-----|
| **Error messages** | Better, more actionable | Good |
| **API ergonomics** | Cleaner, more intuitive | Established but complex |
| **Binary support** | First-class with `binary` module | Requires more setup |
| **Maintenance** | Active development | Mature but slower updates |
| **Performance** | Comparable to nom | Excellent |

[winnow documentation](https://docs.rs/winnow/latest/winnow/index.html) explicitly targets binary parsing with dedicated combinators.

### 3.2 Binary Parsing Combinators

winnow provides these binary-specific combinators:

```rust
use winnow::binary::{be_u32, le_u16, length_take, Endianness};
use winnow::combinator::{repeat, preceded};

// Parse a u32 in native endian
fn parse_u32_ne(input: &mut &[u8]) -> PResult<u32> {
    if cfg!(target_endian = "little") {
        le_u32.parse_next(input)
    } else {
        be_u32.parse_next(input)
    }
}

// Parse a length-prefixed slice (like netlink attributes)
fn parse_attr(input: &mut &[u8]) -> PResult<(u16, &[u8])> {
    let len: u16 = le_u16.parse_next(input)?;
    let attr_type: u16 = le_u16.parse_next(input)?;
    let payload_len = (len as usize).saturating_sub(4);
    let payload = take(payload_len).parse_next(input)?;
    // Handle alignment padding
    let aligned = nla_align(len as usize);
    take(aligned - len as usize).parse_next(input)?;
    Ok((attr_type, payload))
}
```

### 3.3 Structured Message Parsing

```rust
use winnow::prelude::*;

/// Parsed address message with all attributes resolved
#[derive(Debug, Clone)]
pub struct AddressMessage {
    pub header: IfAddrMsg,
    pub address: Option<IpAddr>,
    pub local: Option<IpAddr>,
    pub label: Option<String>,
    pub broadcast: Option<IpAddr>,
    pub flags: AddressFlags,
    pub cache_info: Option<IfaCacheInfo>,
}

impl FromNetlink for AddressMessage {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse fixed header
        let header = IfAddrMsg::parse.parse_next(input)?;
        
        // Parse all attributes into a typed structure
        let mut msg = AddressMessage {
            header,
            address: None,
            local: None,
            label: None,
            broadcast: None,
            flags: AddressFlags::empty(),
            cache_info: None,
        };
        
        // Parse attributes until end of input
        while !input.is_empty() {
            let (attr_type, attr_data) = parse_attr.parse_next(input)?;
            
            match IfaAttr::from(attr_type) {
                IfaAttr::Address => {
                    msg.address = Some(parse_ip_addr(attr_data, header.family)?);
                }
                IfaAttr::Local => {
                    msg.local = Some(parse_ip_addr(attr_data, header.family)?);
                }
                IfaAttr::Label => {
                    msg.label = Some(parse_cstring(attr_data)?);
                }
                IfaAttr::Broadcast => {
                    msg.broadcast = Some(parse_ip_addr(attr_data, header.family)?);
                }
                IfaAttr::Flags => {
                    msg.flags = AddressFlags::from_bits_truncate(parse_u32_ne(attr_data)?);
                }
                IfaAttr::Cacheinfo => {
                    msg.cache_info = Some(IfaCacheInfo::parse.parse(attr_data)?);
                }
                _ => {} // Ignore unknown attributes
            }
        }
        
        Ok(msg)
    }
}
```

---

## 4. Derive Macro Approach

### 4.1 Message Definition

```rust
use rip_netlink_derive::{NetlinkMessage, NetlinkAttr};

/// Address message with automatic parsing/serialization
#[derive(Debug, Clone, NetlinkMessage)]
#[netlink(header = IfAddrMsg)]
pub struct AddressMessage {
    #[netlink(header)]
    pub header: IfAddrMsg,
    
    #[netlink(attr = IFA_ADDRESS, parse_with = "parse_ip_addr")]
    pub address: Option<IpAddr>,
    
    #[netlink(attr = IFA_LOCAL, parse_with = "parse_ip_addr")]
    pub local: Option<IpAddr>,
    
    #[netlink(attr = IFA_LABEL)]
    pub label: Option<String>,
    
    #[netlink(attr = IFA_BROADCAST, parse_with = "parse_ip_addr")]
    pub broadcast: Option<IpAddr>,
    
    #[netlink(attr = IFA_FLAGS)]
    pub flags: Option<u32>,
    
    #[netlink(attr = IFA_CACHEINFO, nested)]
    pub cache_info: Option<IfaCacheInfo>,
}
```

### 4.2 Generated Code

The derive macro would generate:

```rust
impl FromNetlink for AddressMessage {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let header = IfAddrMsg::parse.parse_next(input)?;
        let mut address = None;
        let mut local = None;
        let mut label = None;
        let mut broadcast = None;
        let mut flags = None;
        let mut cache_info = None;
        
        while !input.is_empty() {
            let (attr_type, attr_data) = parse_attr.parse_next(input)?;
            match attr_type {
                1 /* IFA_ADDRESS */ => {
                    address = Some(parse_ip_addr(attr_data, header.ifa_family)?);
                }
                2 /* IFA_LOCAL */ => {
                    local = Some(parse_ip_addr(attr_data, header.ifa_family)?);
                }
                3 /* IFA_LABEL */ => {
                    label = Some(String::from_utf8_lossy(attr_data).trim_end_matches('\0').to_string());
                }
                4 /* IFA_BROADCAST */ => {
                    broadcast = Some(parse_ip_addr(attr_data, header.ifa_family)?);
                }
                8 /* IFA_FLAGS */ => {
                    flags = Some(u32::from_ne_bytes(attr_data.try_into()?));
                }
                6 /* IFA_CACHEINFO */ => {
                    cache_info = Some(IfaCacheInfo::parse.parse(attr_data)?);
                }
                _ => {}
            }
        }
        
        Ok(Self { header, address, local, label, broadcast, flags, cache_info })
    }
}

impl ToNetlink for AddressMessage {
    fn netlink_len(&self) -> usize {
        IfAddrMsg::SIZE
            + self.address.as_ref().map(|_| nla_size(16)).unwrap_or(0)
            + self.local.as_ref().map(|_| nla_size(16)).unwrap_or(0)
            + self.label.as_ref().map(|s| nla_size(s.len() + 1)).unwrap_or(0)
            // ...
    }
    
    fn write_to(&self, builder: &mut MessageBuilder) -> Result<()> {
        builder.append(&self.header);
        if let Some(addr) = &self.address {
            builder.append_attr(1, &addr.octets());
        }
        if let Some(local) = &self.local {
            builder.append_attr(2, &local.octets());
        }
        if let Some(label) = &self.label {
            builder.append_attr_str(3, label);
        }
        // ...
        Ok(())
    }
}
```

### 4.3 Attribute Type Definitions

```rust
/// Typed attribute enum with value information
#[derive(Debug, Clone, NetlinkAttr)]
#[repr(u16)]
pub enum IfaAttr {
    #[netlink(value_type = "()")]
    Unspec = 0,
    
    #[netlink(value_type = "IpAddr", parse_with = "parse_ip_addr")]
    Address = 1,
    
    #[netlink(value_type = "IpAddr", parse_with = "parse_ip_addr")]
    Local = 2,
    
    #[netlink(value_type = "String")]
    Label = 3,
    
    #[netlink(value_type = "IpAddr", parse_with = "parse_ip_addr")]
    Broadcast = 4,
    
    #[netlink(value_type = "IpAddr", parse_with = "parse_ip_addr")]
    Anycast = 5,
    
    #[netlink(value_type = "IfaCacheInfo", nested)]
    Cacheinfo = 6,
    
    #[netlink(value_type = "[u8; 6]")]
    Multicast = 7,
    
    #[netlink(value_type = "u32")]
    Flags = 8,
}
```

---

## 5. Type-Safe Builder API

### 5.1 Current (Unsafe)

```rust
// Can make mistakes with no compile-time checking
let mut builder = MessageBuilder::new(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK);
builder.append(&ifaddr);
builder.append_attr(1, &addr.octets());  // Is 1 the right type? Who knows!
builder.append_attr(999, &data);          // Invalid, but compiles fine
```

### 5.2 Proposed (Type-Safe)

```rust
// Compile-time type checking
let msg = AddressMessageBuilder::new()
    .family(AddressFamily::Inet)
    .index(ifindex)
    .prefix_len(24)
    .scope(Scope::Universe)
    .address(IpAddr::V4(addr))     // Type-checked: must be IpAddr
    .local(IpAddr::V4(local))      // Type-checked: must be IpAddr
    .label("eth0")                  // Type-checked: must be &str
    .build()?;                      // Validates required fields

// This won't compile:
// .address(999)  // Error: expected IpAddr, found i32
```

### 5.3 Builder Implementation

```rust
#[derive(Default)]
pub struct AddressMessageBuilder {
    header: IfAddrMsg,
    address: Option<IpAddr>,
    local: Option<IpAddr>,
    label: Option<String>,
    broadcast: Option<IpAddr>,
    flags: Option<u32>,
}

impl AddressMessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn family(mut self, family: AddressFamily) -> Self {
        self.header.ifa_family = family as u8;
        self
    }
    
    pub fn index(mut self, index: u32) -> Self {
        self.header.ifa_index = index;
        self
    }
    
    pub fn prefix_len(mut self, len: u8) -> Self {
        self.header.ifa_prefixlen = len;
        self
    }
    
    pub fn address(mut self, addr: IpAddr) -> Self {
        self.address = Some(addr);
        self
    }
    
    pub fn local(mut self, addr: IpAddr) -> Self {
        self.local = Some(addr);
        self
    }
    
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
    
    pub fn build(self) -> Result<AddressMessage> {
        // Validate required fields
        let address = self.address.ok_or(Error::MissingField("address"))?;
        
        Ok(AddressMessage {
            header: self.header,
            address: Some(address),
            local: self.local,
            label: self.label,
            broadcast: self.broadcast,
            flags: self.flags,
            cache_info: None,
        })
    }
}
```

---

## 6. Nested Attribute Handling

### 6.1 Current Approach

```rust
// Manual nested parsing (from link.rs)
for (attr_type, attr_data) in AttrIter::new(attrs_data) {
    match IflaAttr::from(attr_type) {
        IflaAttr::Linkinfo => {
            // Must manually iterate nested attributes
            for (info_type, info_data) in AttrIter::new(attr_data) {
                match IflaInfo::from(info_type) {
                    IflaInfo::Kind => {
                        kind = Some(get::string(info_data)?.to_string());
                    }
                    IflaInfo::Data => {
                        // Must know what kind to parse Data correctly!
                        if kind == Some("vlan") {
                            // Parse VLAN-specific attributes
                        } else if kind == Some("bridge") {
                            // Parse bridge-specific attributes
                        }
                        // ... etc
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}
```

### 6.2 Proposed Approach

```rust
#[derive(Debug, Clone, NetlinkMessage)]
#[netlink(header = IfInfoMsg)]
pub struct LinkMessage {
    #[netlink(header)]
    pub header: IfInfoMsg,
    
    #[netlink(attr = IFLA_IFNAME)]
    pub name: Option<String>,
    
    #[netlink(attr = IFLA_MTU)]
    pub mtu: Option<u32>,
    
    #[netlink(attr = IFLA_LINKINFO, nested)]
    pub link_info: Option<LinkInfo>,
}

#[derive(Debug, Clone, NetlinkMessage)]
pub struct LinkInfo {
    #[netlink(attr = IFLA_INFO_KIND)]
    pub kind: Option<String>,
    
    #[netlink(attr = IFLA_INFO_DATA, nested, dynamic)]
    pub data: Option<LinkInfoData>,
}

/// Dynamic dispatch based on `kind` field
#[derive(Debug, Clone)]
pub enum LinkInfoData {
    Vlan(VlanInfo),
    Bridge(BridgeInfo),
    Bond(BondInfo),
    Vxlan(VxlanInfo),
    Unknown(Vec<u8>),
}
```

---

## 7. Comparison with Existing Crates

### 7.1 netlink-packet-route

[netlink-packet-route](https://github.com/rust-netlink/netlink-packet-route) is the most mature Rust netlink implementation.

**Pros:**
- Battle-tested, widely used
- Complete protocol coverage
- Good type definitions

**Cons:**
- Heavy dependency tree (many sub-crates)
- API is low-level, still requires manual parsing
- Not async-native (requires rtnetlink wrapper)

### 7.2 rtnetlink

[rtnetlink](https://github.com/rust-netlink/rtnetlink) provides a higher-level API.

**Pros:**
- Request builder pattern (`handle.link().get().execute()`)
- Async-native
- Handles netlink protocol details

**Cons:**
- Still returns low-level message types
- User must iterate attributes manually for complex cases

### 7.3 nlink (Proposed)

**Goal:** Combine the best of both with:
- Zero-copy parsing via winnow
- Derive macros for automatic parsing/serialization
- Type-safe builders with validation
- First-class async support
- Minimal dependencies

---

## 8. Implementation Plan

### Phase 1: Parser Foundation (2-3 days)

1. Add `winnow` dependency
2. Create `nlink/src/parse.rs` with core combinators:
   - `parse_nlmsghdr`
   - `parse_attr`
   - `parse_u8/u16/u32/u64` (native endian)
   - `parse_cstring`
   - `parse_ip_addr`
3. Define `FromNetlink` and `ToNetlink` traits
4. Implement for basic types (`IfInfoMsg`, `IfAddrMsg`, `RtMsg`, `TcMsg`)

### Phase 2: Derive Macros (3-4 days)

1. Create `nlink-derive` crate
2. Implement `#[derive(NetlinkMessage)]`:
   - Parse header struct
   - Generate attribute iteration
   - Handle optional fields
3. Implement `#[derive(NetlinkAttr)]`:
   - Generate `From<u16>` and `Into<u16>`
   - Attach value type information
4. Add nested attribute support

### Phase 3: High-Level Message Types (2-3 days)

1. Define strongly-typed messages:
   - `AddressMessage`, `RouteMessage`, `LinkMessage`
   - `NeighborMessage`, `RuleMessage`
   - `QdiscMessage`, `ClassMessage`, `FilterMessage`
2. Implement builders with validation
3. Add helper methods (`LinkMessage::is_up()`, `RouteMessage::is_default()`)

### Phase 4: Refactor Binaries (2-3 days)

1. Replace manual parsing with `Message::parse()`
2. Replace `MessageBuilder` with typed builders
3. Remove boilerplate from command implementations
4. Verify all existing functionality works

### Phase 5: Documentation & Testing (1-2 days)

1. Add comprehensive doc comments
2. Create usage examples
3. Add property-based tests (with `proptest` or `quickcheck`)
4. Benchmark parsing performance

---

## 9. API Usage Examples

### 9.1 Listing Addresses

**Current:**
```rust
let responses = conn.dump(dump_request(RTM_GETADDR)).await?;
for response in responses {
    if let Some(addr) = parse_addr_message(&response)? {
        println!("{}: {}/{}", addr.index, addr.address, addr.prefix_len);
    }
}
```

**Proposed:**
```rust
let addresses: Vec<AddressMessage> = conn.dump_typed(RTM_GETADDR).await?;
for addr in addresses {
    println!("{}: {}/{}", 
        addr.header.ifa_index, 
        addr.address.unwrap_or_default(),
        addr.header.ifa_prefixlen
    );
}
```

### 9.2 Adding a Route

**Current:**
```rust
let mut builder = ack_request(RTM_NEWROUTE);
let rtmsg = RtMsg::new()
    .with_family(2)
    .with_dst_len(24)
    .with_table(254);
builder.append(&rtmsg);
builder.append_attr(RtaAttr::Dst as u16, &dst.octets());
builder.append_attr(RtaAttr::Gateway as u16, &gw.octets());
builder.append_attr(RtaAttr::Oif as u16, &ifindex.to_ne_bytes());
conn.request_ack(builder).await?;
```

**Proposed:**
```rust
let route = RouteMessage::builder()
    .family(AddressFamily::Inet)
    .destination(dst, 24)
    .gateway(gw)
    .output_interface(ifindex)
    .table(RouteTable::Main)
    .build()?;

conn.add(route).await?;
```

### 9.3 Event Monitoring

**Current:**
```rust
let stream = conn.subscribe(RTNLGRP_LINK)?;
while let Some(msg) = stream.next().await {
    let data = msg?;
    let header = NlMsgHdr::from_bytes(&data)?;
    match header.nlmsg_type {
        RTM_NEWLINK => {
            if let Some(link) = parse_link_message(&data)? {
                println!("Link added: {}", link.name);
            }
        }
        // ... manual dispatch
    }
}
```

**Proposed:**
```rust
let mut events = conn.subscribe::<LinkEvent>(RTNLGRP_LINK)?;
while let Some(event) = events.next().await {
    match event? {
        LinkEvent::New(link) => println!("Link added: {}", link.name()),
        LinkEvent::Del(link) => println!("Link removed: {}", link.name()),
        LinkEvent::Change { old, new } => println!("Link changed: {}", new.name()),
    }
}
```

---

## 10. Recommendations

### 10.1 Immediate Actions

1. **Add winnow dependency** - It's well-suited for binary parsing and actively maintained
2. **Create parser module** - Start with core combinators, build up
3. **Keep low-level API** - Don't remove `MessageBuilder`/`AttrIter`, add high-level on top

### 10.2 Design Principles

1. **Zero-copy where possible** - Use `&[u8]` and lifetime-bound types
2. **Fail explicitly** - Return `Result`, don't silently skip malformed data
3. **Type everything** - Use newtypes for IDs, indices, flags
4. **Document invariants** - Make required vs optional clear in types

### 10.3 Testing Strategy

1. **Roundtrip tests** - Parse → serialize → parse must be identical
2. **Fuzz testing** - Use `cargo-fuzz` with AFL/libfuzzer
3. **Kernel compatibility** - Test against live netlink (in CI with network namespace)
4. **Property tests** - Generate random valid messages, verify parsing

---

## 11. Conclusion

The current nlink implementation is functional but requires too much boilerplate from library consumers. By adding:

1. **winnow-based parsing** for zero-copy, type-safe message parsing
2. **Derive macros** for automatic implementation of traits
3. **Type-safe builders** for message construction
4. **Strongly-typed message structs** with all attributes resolved

We can reduce ~300 lines of parsing code per binary to ~20 lines while gaining compile-time safety guarantees. This positions nlink as a superior library choice over existing options like netlink-packet-route.

---

## References

- [winnow documentation](https://docs.rs/winnow/latest/winnow/index.html)
- [winnow binary parsing](https://docs.rs/winnow/latest/winnow/binary/index.html)
- [winnow binary parsing discussion](https://github.com/winnow-rs/winnow/discussions/85)
- [netlink-packet-route](https://github.com/rust-netlink/netlink-packet-route)
- [rtnetlink](https://github.com/rust-netlink/rtnetlink)
- [nom parser combinator](https://github.com/rust-bakery/nom)
