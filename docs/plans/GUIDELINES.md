# Implementation Guidelines

All implementations in nlink must follow these guidelines:

## Core Dependencies

| Crate | Purpose |
|-------|---------|
| `zerocopy` | Zero-copy serialization/deserialization of fixed-size kernel structures |
| `winnow` | Parser combinators for variable-length TLV attribute parsing |
| `tokio` | Async runtime and I/O |
| `thiserror` | Derive macro for error types |

## Zerocopy vs Winnow: When to Use Each

The distinction is based on **structure type**:

| Structure Type | Tool | Example |
|----------------|------|---------|
| Fixed-size kernel headers | `zerocopy` | `TcMsg`, `IfInfoMsg`, `NhMsg`, `CnMsg` |
| Variable-length TLV attributes | `winnow` | Netlink attribute parsing in `FromNetlink` |

**Rule of thumb:**
- If it's a `#[repr(C)]` struct that maps directly to a kernel structure → **zerocopy**
- If you're parsing nested TLV (Type-Length-Value) netlink attributes → **winnow**

**Do NOT use winnow for fixed-size structures.** Zerocopy is more efficient and safer:

```rust
// WRONG: Using winnow for fixed-size struct
fn parse(input: &mut &[u8]) -> PResult<CnMsg> {
    let idx = le_u32.parse_next(input)?;
    let val = le_u32.parse_next(input)?;
    // ... manually parse each field
}

// CORRECT: Using zerocopy for fixed-size struct
fn from_bytes(data: &[u8]) -> Option<&CnMsg> {
    CnMsg::ref_from_prefix(data).map(|(r, _)| r).ok()
}
```

## 1. Strongly Typed

- Use typed enums instead of raw integers for constants
- Use builder patterns with typed methods, not string parameters
- Use `IpAddr`, `Ipv4Addr`, `Ipv6Addr` from std::net
- Prefer `[u8; 6]` for MAC addresses with helper methods

```rust
// Good
pub enum NexthopGroupType {
    Multipath,
    Resilient,
}

// Bad
pub const NEXTHOP_GRP_TYPE_MPATH: u16 = 0;
```

## 2. High Level API

- Hide netlink complexity from users
- Provide `Connection<Protocol>` methods for common operations
- Use builders for complex configurations
- Return strongly-typed message structs, not raw bytes

```rust
// Good
conn.add_nexthop(NexthopBuilder::new(1).gateway(ip).dev("eth0")).await?;

// Bad
conn.send_raw_message(&build_nexthop_msg(1, ip, "eth0")).await?;
```

## 3. Async (Tokio)

- All `Connection` methods that do I/O must be `async`
- Use `tokio::net` for socket operations
- Stream implementations must be compatible with `tokio-stream`

```rust
// Good
pub async fn get_nexthops(&self) -> Result<Vec<Nexthop>>;

// Bad
pub fn get_nexthops(&self) -> Result<Vec<Nexthop>>;
```

## 4. Zerocopy for Kernel Structures

All `#[repr(C)]` structures that map to kernel types must use zerocopy:

```rust
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NhMsg {
    pub nh_family: u8,
    pub nh_scope: u8,
    pub nh_protocol: u8,
    pub resvd: u8,
    pub nh_flags: u32,
}

impl NhMsg {
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
    
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}
```

## 5. Winnow for TLV Attribute Parsing

Winnow is used **only** for parsing variable-length TLV (Type-Length-Value) netlink attributes, **not** for fixed-size structures.

The `FromNetlink` trait combines both approaches:
1. **zerocopy** for the fixed header
2. **winnow** for iterating over TLV attributes

```rust
use winnow::binary::le_u16;
use winnow::prelude::*;
use winnow::token::take;

use crate::netlink::parse::{FromNetlink, PResult};

impl FromNetlink for NexthopMessage {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // 1. Parse fixed header with ZEROCOPY (not winnow!)
        let header_bytes: &[u8] = take(NhMsg::SIZE).parse_next(input)?;
        let header = NhMsg::from_bytes(header_bytes)
            .ok_or_else(|| winnow::error::ErrMode::Cut(
                winnow::error::ContextError::new()
            ))?;
        
        let mut msg = NexthopMessage {
            header: *header,
            ..Default::default()
        };
        
        // 2. Parse TLV attributes with WINNOW
        while !input.is_empty() && input.len() >= 4 {
            let len = le_u16.parse_next(input)? as usize;
            let attr_type = le_u16.parse_next(input)?;
            
            if len < 4 { break; }
            let payload_len = len.saturating_sub(4);
            let attr_data: &[u8] = take(payload_len).parse_next(input)?;
            
            // Align to 4 bytes
            let aligned = (len + 3) & !3;
            let padding = aligned.saturating_sub(len);
            if input.len() >= padding {
                let _: &[u8] = take(padding).parse_next(input)?;
            }
            
            // Match on attribute type and parse payload
            match attr_type {
                NHA_ID => msg.id = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap())),
                NHA_GATEWAY => msg.gateway = parse_gateway(attr_data),
                // ...
            }
        }
        
        Ok(msg)
    }
}
```

**Key points:**
- Fixed headers: use `zerocopy::ref_from_prefix()` via the struct's `from_bytes()` method
- TLV iteration: use winnow's `take()` and `le_u16` for length/type parsing
- Attribute payloads: use zerocopy or simple `from_ne_bytes()` depending on complexity

## 6. Error Handling (thiserror)

Use `thiserror` for deriving error types. Errors should be informative and include context:

```rust
use thiserror::Error;

/// Errors for MACsec operations.
#[derive(Debug, Error)]
pub enum MacsecError {
    /// Invalid cipher suite.
    #[error("invalid cipher suite: {0}")]
    InvalidCipher(String),
    
    /// Key length mismatch.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    /// Underlying netlink error.
    #[error("netlink error: {0}")]
    Netlink(#[from] crate::netlink::Error),
}
```

For module-specific errors that convert to the main `Error` type:

```rust
// In the module
#[derive(Debug, Error)]
pub enum MacsecError { ... }

// Implement From for the main error type
impl From<MacsecError> for crate::netlink::Error {
    fn from(e: MacsecError) -> Self {
        Error::InvalidMessage(e.to_string())
    }
}
```

## Compliance Checklist

For each new feature, verify:

- [ ] Kernel structures use `#[repr(C)]` + zerocopy derives
- [ ] Message parsing implements `FromNetlink` trait with winnow
- [ ] All I/O methods are `async`
- [ ] API uses typed builders, not string parameters
- [ ] Enums are used for constants with known values
- [ ] Connection methods return strongly-typed results
- [ ] Errors use `thiserror` with informative messages
