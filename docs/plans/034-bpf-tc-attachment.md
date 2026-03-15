# Plan 034: BPF/TC Attachment Improvements

## Overview

`BpfFilter` already exists in `filter.rs:1021-1139` with FD-based program attachment and direct action support. This plan covers the remaining gaps:

1. **Pinned path loading** — Attach by `/sys/fs/bpf/` path instead of raw FD
2. **BPF info parsing** — Read program ID, name, and tag from attached filters
3. **Convenience helpers** — Common clsact + BPF attachment pattern

## Progress

### Pinned Path Support
- [ ] Implement `BpfFilter::from_pinned()` method
- [ ] Add unit test for `from_pinned()` with valid/invalid paths
- [ ] Add doc comments with examples on `from_pinned()`

### BPF Info Parsing
- [ ] Add `TCA_BPF_*` constants (1-11)
- [ ] Implement `BpfInfo` struct with id, name, tag, direct_action, classid
- [ ] Implement `tag_hex()` method
- [ ] Implement `bpf_info()` on `TcMessage`
- [ ] Add integration test for BPF info parsing
- [ ] Add BPF info display in `bins/tc` filter show output
- [ ] Add doc comments with examples

### Convenience Helpers
- [ ] Implement `BpfDirection` enum (Ingress/Egress)
- [ ] Implement `attach_bpf()` on `Connection<Route>`
- [ ] Implement `attach_bpf_by_index()` (namespace-safe)
- [ ] Implement `detach_bpf()` on `Connection<Route>`
- [ ] Implement `list_bpf_programs()` on `Connection<Route>`
- [ ] Add integration test for attach/detach/list cycle
- [ ] Add BPF attachment support to `bins/tc` filter add command
- [ ] Add doc comments with examples on convenience methods
- [ ] Update CLAUDE.md with BPF/TC usage examples

## Current State

`BpfFilter` supports:
- `new(fd)` — Attach by file descriptor
- `name()` — Set program name
- `direct_action()` — DA mode (`TCA_BPF_FLAG_ACT_DIRECT`)
- `classid()` — Target class (non-DA mode)
- `priority()`, `protocol()`, `chain()`
- Full `FilterConfig` trait implementation

## Kernel Constants (verified against linux/pkt_cls.h, kernel 6.19.6)

### TCA_BPF_* Attributes

| Constant | Value | Type |
|----------|-------|------|
| `TCA_BPF_ACT` | 1 | nested (actions) |
| `TCA_BPF_POLICE` | 2 | nested |
| `TCA_BPF_CLASSID` | 3 | u32 |
| `TCA_BPF_OPS_LEN` | 4 | u16 |
| `TCA_BPF_OPS` | 5 | binary |
| `TCA_BPF_FD` | 6 | u32 (raw fd) |
| `TCA_BPF_NAME` | 7 | string |
| `TCA_BPF_FLAGS` | 8 | u32 |
| `TCA_BPF_FLAGS_GEN` | 9 | u32 |
| `TCA_BPF_TAG` | 10 | [u8; 8] |
| `TCA_BPF_ID` | 11 | u32 |

Flag: `TCA_BPF_FLAG_ACT_DIRECT = 1`

## Implementation

### 1. Pinned Path Support

Load a BPF program from a pinned path in `/sys/fs/bpf/`:

```rust
use std::path::Path;
use std::os::unix::io::IntoRawFd;

impl BpfFilter {
    /// Create a BPF filter from a pinned program path.
    ///
    /// Opens the pinned BPF program at the given path and uses the
    /// resulting file descriptor. The program must be pinned via
    /// `bpf_obj_pin()` or `bpftool map pin`.
    ///
    /// # Errors
    ///
    /// Returns `Error::Io` if the path doesn't exist or isn't a valid
    /// BPF program pin.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::filter::BpfFilter;
    ///
    /// let filter = BpfFilter::from_pinned("/sys/fs/bpf/my_prog")?
    ///     .direct_action();
    /// conn.add_filter("eth0", "ingress", filter).await?;
    /// ```
    pub fn from_pinned(path: impl AsRef<Path>) -> Result<Self> {
        let file = std::fs::File::open(path.as_ref())?;
        Ok(Self::new(file.into_raw_fd()))
    }
}
```

### 2. BPF Info Parsing

Parse BPF-specific attributes from filter dump responses:

```rust
/// Information about an attached BPF program.
///
/// Parsed from `TCA_BPF_*` attributes in TC filter dump responses.
#[derive(Debug, Clone)]
pub struct BpfInfo {
    /// BPF program ID (stable kernel identifier).
    pub id: Option<u32>,
    /// BPF program name (set by the loader).
    pub name: Option<String>,
    /// BPF program tag (8-byte SHA-1 truncation of instructions).
    pub tag: Option<[u8; 8]>,
    /// Whether direct action mode is enabled.
    pub direct_action: bool,
    /// TC classid (for non-DA mode).
    pub classid: Option<u32>,
}

impl BpfInfo {
    /// Format the tag as a hex string (e.g., "a1b2c3d4e5f6a7b8").
    pub fn tag_hex(&self) -> Option<String> {
        self.tag.map(|t| t.iter().map(|b| format!("{b:02x}")).collect())
    }
}

impl TcMessage {
    /// Get BPF program info if this is a BPF filter.
    ///
    /// Returns `None` if the filter kind is not "bpf".
    ///
    /// # Example
    ///
    /// ```ignore
    /// let filters = conn.get_filters_by_name("eth0", "ingress").await?;
    /// for filter in &filters {
    ///     if let Some(bpf) = filter.bpf_info() {
    ///         println!("BPF: id={:?} name={:?} tag={:?} da={}",
    ///             bpf.id, bpf.name, bpf.tag_hex(), bpf.direct_action);
    ///     }
    /// }
    /// ```
    pub fn bpf_info(&self) -> Option<BpfInfo> {
        if self.kind() != Some("bpf") {
            return None;
        }

        let mut info = BpfInfo {
            id: None, name: None, tag: None,
            direct_action: false, classid: None,
        };

        for attr in self.options_attrs() {
            match attr.attr_type() {
                TCA_BPF_ID => info.id = attr.payload_u32(),
                TCA_BPF_NAME => info.name = attr.payload_str().map(String::from),
                TCA_BPF_TAG => {
                    if attr.payload().len() == 8 {
                        let mut tag = [0u8; 8];
                        tag.copy_from_slice(attr.payload());
                        info.tag = Some(tag);
                    }
                }
                TCA_BPF_FLAGS => {
                    if let Some(flags) = attr.payload_u32() {
                        info.direct_action = (flags & TCA_BPF_FLAG_ACT_DIRECT) != 0;
                    }
                }
                TCA_BPF_CLASSID => info.classid = attr.payload_u32(),
                _ => {}
            }
        }

        Some(info)
    }
}
```

### 3. Convenience: clsact + BPF Attachment

The most common BPF TC pattern:

```bash
tc qdisc add dev eth0 clsact
tc filter add dev eth0 ingress bpf da obj prog.o
```

```rust
/// Direction for BPF program attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfDirection {
    /// Ingress (clsact ingress hook).
    Ingress,
    /// Egress (clsact egress hook).
    Egress,
}

impl Connection<Route> {
    /// Attach a BPF program to ingress or egress using clsact.
    ///
    /// Creates the clsact qdisc if it doesn't exist, then attaches the
    /// BPF filter. This is the standard pattern for BPF TC programs.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::filter::{BpfFilter, BpfDirection};
    ///
    /// let filter = BpfFilter::from_pinned("/sys/fs/bpf/my_prog")?
    ///     .direct_action();
    /// conn.attach_bpf("eth0", BpfDirection::Ingress, filter).await?;
    /// ```
    pub async fn attach_bpf(
        &self,
        iface: impl Into<InterfaceRef>,
        direction: BpfDirection,
        filter: BpfFilter,
    ) -> Result<()> {
        let ifindex = self.resolve_ifindex(&iface.into()).await?;
        self.attach_bpf_by_index(ifindex, direction, filter).await
    }

    /// Attach a BPF program by interface index (namespace-safe).
    pub async fn attach_bpf_by_index(
        &self,
        ifindex: u32,
        direction: BpfDirection,
        filter: BpfFilter,
    ) -> Result<()> {
        // Add clsact qdisc (ignore EEXIST)
        match self.add_qdisc_by_index(ifindex, ClsactConfig::new()).await {
            Ok(()) => {}
            Err(e) if e.is_already_exists() => {}
            Err(e) => return Err(e),
        }

        let parent = match direction {
            BpfDirection::Ingress => "ingress",
            BpfDirection::Egress => "egress",
        };

        self.add_filter_by_index(ifindex, parent, filter).await
    }

    /// Detach all BPF filters from an interface direction.
    pub async fn detach_bpf(
        &self,
        iface: impl Into<InterfaceRef>,
        direction: BpfDirection,
    ) -> Result<()> {
        let ifindex = self.resolve_ifindex(&iface.into()).await?;
        let parent = match direction {
            BpfDirection::Ingress => "ingress",
            BpfDirection::Egress => "egress",
        };
        self.flush_filters_by_index(ifindex, parent).await
    }

    /// List attached BPF programs on an interface (both directions).
    pub async fn list_bpf_programs(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<BpfInfo>> {
        let ifindex = self.resolve_ifindex(&iface.into()).await?;
        let mut programs = Vec::new();

        for parent in ["ingress", "egress"] {
            let filters = self.get_filters_by_index(ifindex, parent).await?;
            for filter in &filters {
                if let Some(info) = filter.bpf_info() {
                    programs.push(info);
                }
            }
        }

        Ok(programs)
    }
}
```

## Files to Modify

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/filter.rs` | Add `from_pinned()`, `TCA_BPF_*` constants |
| `crates/nlink/src/netlink/messages/tc.rs` | Add `bpf_info()` to `TcMessage` |
| `crates/nlink/src/netlink/connection.rs` | Add `attach_bpf()`, `detach_bpf()`, `list_bpf_programs()` |

## Estimated Effort

| Task | Effort |
|------|--------|
| `from_pinned()` | 30 min |
| `TCA_BPF_*` constants | 15 min |
| `BpfInfo` parsing | 2 hours |
| `attach_bpf()` / `detach_bpf()` | 1 hour |
| `list_bpf_programs()` | 30 min |
| Tests | 1 hour |
| **Total** | ~5 hours |

## Notes

- The FD is passed as a `u32` attribute (`TCA_BPF_FD`), no `SCM_RIGHTS` needed
- The FD must reference a `BPF_PROG_TYPE_SCHED_CLS` program
- This plan does not cover BPF program **loading** — use aya or libbpf-rs
- `from_pinned()` transfers FD ownership via `into_raw_fd()`
- The tag is an 8-byte SHA-1 truncation of BPF instructions
