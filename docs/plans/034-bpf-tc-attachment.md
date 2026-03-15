# Plan 034: BPF/XDP TC Attachment Improvements

## Overview

`BpfFilter` already exists in `filter.rs:1021-1139` with FD-based program attachment and direct action support. This plan covers the remaining gaps:

1. **Pinned path loading** - Attach by `/sys/fs/bpf/` path instead of raw FD
2. **BPF info parsing** - Read program ID, name, and tag from attached filters
3. **Convenience helpers** - Common clsact + BPF attachment pattern

## Current State

`BpfFilter` already supports:
- `new(fd)` - Attach by file descriptor
- `name()` - Set program name
- `direct_action()` - DA mode (`TCA_BPF_FLAG_ACT_DIRECT`)
- `classid()` - Target class (non-DA mode)
- `priority()`, `protocol()`, `chain()`
- Full `FilterConfig` trait implementation with `write_options()`

## Missing

### 1. Pinned Path Support

Load a BPF program from a pinned path in `/sys/fs/bpf/`:

```rust
impl BpfFilter {
    /// Create a BPF filter from a pinned program path.
    ///
    /// Opens the pinned BPF program and uses the resulting FD.
    /// Requires the program to be pinned via `bpf_obj_pin()` or `bpftool`.
    pub fn from_pinned(path: impl AsRef<Path>) -> Result<Self> {
        let fd = std::fs::File::open(path.as_ref())?;
        Ok(Self::new(fd.into_raw_fd()))
    }
}
```

### 2. BPF Info Parsing

Parse BPF-specific attributes from filter dump responses:

```rust
/// Information about an attached BPF program.
#[derive(Debug, Clone)]
pub struct BpfInfo {
    pub id: Option<u32>,          // TCA_BPF_ID
    pub name: Option<String>,     // TCA_BPF_NAME
    pub tag: Option<[u8; 8]>,     // TCA_BPF_TAG (8-byte program hash)
    pub direct_action: bool,      // TCA_BPF_FLAGS & TCA_BPF_FLAG_ACT_DIRECT
}

impl TcMessage {
    /// Get BPF program info if this is a BPF filter.
    pub fn bpf_info(&self) -> Option<BpfInfo> {
        if self.kind() != Some("bpf") {
            return None;
        }
        // Parse TCA_BPF_ID, TCA_BPF_NAME, TCA_BPF_TAG, TCA_BPF_FLAGS
        // from the options attributes
    }
}
```

Kernel attributes to parse:

| Constant | Value | Type |
|----------|-------|------|
| `TCA_BPF_ID` | 11 | u32 |
| `TCA_BPF_NAME` | 7 | string |
| `TCA_BPF_TAG` | 10 | [u8; 8] |
| `TCA_BPF_FLAGS` | 8 | u32 |

### 3. Convenience: clsact + BPF Pattern

The most common BPF TC attachment pattern is:

```bash
tc qdisc add dev eth0 clsact
tc filter add dev eth0 ingress bpf da obj prog.o
```

Add a convenience method:

```rust
impl Connection<Route> {
    /// Attach a BPF program to ingress or egress using clsact.
    ///
    /// Creates the clsact qdisc if it doesn't exist, then attaches the filter.
    pub async fn attach_bpf(
        &self,
        iface: impl Into<InterfaceRef>,
        direction: BpfDirection,
        filter: BpfFilter,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
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
}

pub enum BpfDirection {
    Ingress,
    Egress,
}
```

## Files to Modify

1. `crates/nlink/src/netlink/filter.rs` - Add `from_pinned()`
2. `crates/nlink/src/netlink/messages/tc.rs` - Add `bpf_info()` method, parse TCA_BPF_* from options
3. `crates/nlink/src/netlink/link.rs` or `connection.rs` - Add `attach_bpf()` convenience

## Estimated Effort

| Task | Effort |
|------|--------|
| `from_pinned()` | 30 min |
| BPF info parsing | 2 hours |
| `attach_bpf()` convenience | 1 hour |
| Tests | 1 hour |
| **Total** | ~5 hours |

## Notes

- The FD is passed as a `u32` attribute (`TCA_BPF_FD`), no `SCM_RIGHTS` needed
- The FD must reference a `BPF_PROG_TYPE_SCHED_CLS` program
- This plan intentionally does not cover BPF program **loading** (use aya/libbpf-rs for that)
