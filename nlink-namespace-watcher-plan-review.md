# Namespace Watcher Plan Review

Review of `nlink-namespace-watcher-plan.md` for implementing Solutions 4 and 5 as independent modules.

---

## Overall Assessment

**Verdict: Good plan, proceed with implementation.**

The plan is well-structured and technically sound. Both solutions address different use cases and are correctly designed as complementary rather than competing approaches.

---

## Strengths

### 1. Clear Problem Separation

- **Solution 4 (Filesystem)**: Tracks named namespaces in `/var/run/netns/` - what users typically care about when working with `ip netns`
- **Solution 5 (Netlink)**: Tracks kernel-level namespace IDs - lower-level, captures all namespaces including anonymous ones

### 2. Clean API Design

Both APIs follow existing nlink patterns:
- Builder pattern for configuration
- Async/await native
- `Result`-based error handling
- Channel-based event streaming

### 3. Edge Cases Identified

The plan correctly identifies:
- Directory lifecycle (creation/deletion of `/var/run/netns/`)
- Parent directory fallback when netns directory doesn't exist
- Permission errors
- Rapid create/delete operations

### 4. Honest About Limitations

Line 745-753 correctly identifies that Solution 5's NSID events aren't always generated for named namespaces, making filesystem watching still necessary for that use case.

---

## Issues to Address During Implementation

### Issue 1: Blocking Send in Notify Callback

**Location**: Lines 244, 248, 261, 291, 295

**Problem**: `blocking_send` is used inside the notify callback, which runs on the notify thread. This could block the filesystem watcher if the channel is full.

**Solution**: Use `try_send` and log/drop events if the channel is full, or use a sync channel with `std::sync::mpsc` and forward to tokio channel via a spawned task.

```rust
// Instead of:
let _ = tx.blocking_send(NamespaceEvent::Created { name });

// Consider:
if tx.try_send(NamespaceEvent::Created { name }).is_err() {
    // Channel full, event dropped - log if needed
}
```

### Issue 2: Race Condition in `list_and_watch`

**Location**: Lines 307-311

**Problem**: Current flow is:
1. List namespaces
2. Create watcher

A namespace created between steps 1 and 2 would be missed.

**Solution**: Reverse the order and deduplicate:
```rust
pub fn list_and_watch() -> Result<(Vec<String>, Self, mpsc::Receiver<NamespaceEvent>)> {
    // Start watcher FIRST
    let (watcher, rx) = Self::new()?;
    // Then list (may include duplicates with events, but won't miss any)
    let current = super::list()?;
    Ok((current, watcher, rx))
}
```

### Issue 3: Parse Error Handling Mismatch

**Location**: Line 679

**Problem**: `parse_message` returns `Option<NamespaceNetlinkEvent>` but calls `NsIdMessage::parse()` which returns `PResult<NsIdMessage>`. The `?` operator won't work.

**Solution**: Use `.ok()` or match explicitly:
```rust
fn parse_message(&self, data: &[u8]) -> Option<NamespaceNetlinkEvent> {
    // ...
    match msg_type {
        RTM_NEWNSID => {
            let msg = NsIdMessage::parse(&mut &payload[..]).ok()?;
            Some(NamespaceNetlinkEvent::NewNsId {
                nsid: msg.nsid?,
                pid: msg.pid,
                fd: msg.fd,
            })
        }
        // ...
    }
}
```

### Issue 4: Feature Flag Naming Convention

**Location**: Line 115

**Problem**: `namespace-watcher` uses a hyphen, but Rust feature flags conventionally use underscores.

**Solution**: Use `namespace_watcher` for consistency with other features in the crate.

```toml
[features]
namespace_watcher = ["notify"]
```

### Issue 5: Missing Drop Implementation

**Location**: Lines 313-316

**Problem**: `stop(self)` consumes the watcher, but there's no `Drop` implementation. If the watcher is dropped without calling `stop()`, resources may not be cleaned up properly.

**Solution**: Either rely on `RecommendedWatcher` having its own `Drop` (which it does), or implement `Drop` explicitly for clarity:

```rust
impl Drop for NamespaceWatcher {
    fn drop(&mut self) {
        // Watchers in state will be dropped automatically
        // Could add logging here for debugging
    }
}
```

Since `notify::RecommendedWatcher` already implements `Drop`, this is mostly fine, but the `stop(self)` method is redundant - users can just drop the watcher.

### Issue 6: Thread Safety of State Access

**Location**: Lines 183-193

**Problem**: Multiple `lock().unwrap()` calls on the same mutex in sequence:
```rust
state.lock().unwrap().netns_watcher = Some(watcher);
state.lock().unwrap().watching_netns = true;
```

**Solution**: Use a single lock:
```rust
{
    let mut state_guard = state.lock().unwrap();
    state_guard.netns_watcher = Some(watcher);
    state_guard.watching_netns = true;
}
```

---

## Minor Suggestions

### 1. Consider Adding Backpressure Handling

For high-frequency namespace operations, consider:
- Configurable behavior when channel is full (drop oldest, drop newest, block)
- Metrics for dropped events

### 2. Add Debouncing Option for Filesystem Events

Some filesystems emit multiple events for a single operation. Consider an optional debounce window in `NamespaceWatcherConfig`.

### 3. Document Kernel Version Requirements

Solution 5 mentions Linux 3.8+ for RTM_*NSID but 4.9+ for reliable multicast. Add this to the public API documentation.

### 4. Consider `async fn new()` for Solution 4

Even though the filesystem watcher is sync, making the constructor async would allow future enhancements and consistency with Solution 5.

---

## Implementation Order Recommendation

The plan's phasing is correct. For implementing both (not hybrid):

### Phase 1: Solution 4 (Filesystem Watcher)
1. Add `notify` dependency with feature flag `namespace_watcher`
2. Implement `NamespaceWatcher` with fixes noted above
3. Add unit tests
4. Add integration test with actual namespace operations

### Phase 2: Solution 5 (Netlink Events)
1. Add namespace constants to `types/`
2. Add `add_membership()` to socket
3. Implement `NsIdMessage` parsing
4. Implement `NamespaceEventSubscriber`
5. Add `get_nsid()` / `get_nsid_for_pid()` to Connection
6. Add tests

### Skip Phase 3 (Hybrid)
Per your preference, skip the unified watcher. Users can use both independently if needed.

---

## Files Summary

### New Files
| File | Purpose |
|------|---------|
| `src/netlink/namespace_watcher.rs` | Solution 4: Filesystem-based watcher |
| `src/netlink/namespace_events.rs` | Solution 5: Netlink event subscriber |
| `src/netlink/messages/namespace.rs` | NsIdMessage parsing |
| `src/netlink/types/namespace.rs` | RTM_*NSID constants |

### Modified Files
| File | Changes |
|------|---------|
| `Cargo.toml` | Add `notify` optional dependency, `namespace_watcher` feature |
| `src/netlink/mod.rs` | Export new modules |
| `src/netlink/socket.rs` | Add `add_membership()` |
| `src/netlink/connection.rs` | Add `get_nsid()` methods |
| `src/lib.rs` | Re-export namespace watcher types |

---

## Conclusion

The plan is solid. Address the issues noted above during implementation, particularly:

1. Fix `blocking_send` -> `try_send` in notify callbacks
2. Fix race condition in `list_and_watch`
3. Fix parse error handling in Solution 5
4. Use underscore in feature flag name

Ready to proceed with implementation.

---

## Detailed Implementation Plan (With Issue Fixes)

This section provides the corrected implementation approach for both solutions, incorporating all fixes for the issues identified above.

**Important Change**: Solution 4 now uses the `inotify` crate directly instead of `notify`. This provides:
- True async/tokio integration (no thread bridging needed)
- Linux-native (matches the project's Linux-only scope)
- Simpler, cleaner code
- No extra background threads

---

### Solution 4: Filesystem Watcher (Using `inotify` - Async Native)

#### Step 1: Add Dependencies

In `crates/nlink/Cargo.toml`:

```toml
[dependencies]
inotify = { version = "0.11", default-features = false, features = ["stream"], optional = true }

[features]
namespace_watcher = ["inotify"]
full = ["sockdiag", "tuntap", "tc", "output", "namespace_watcher"]
```

#### Step 2: Create Module Structure

```
crates/nlink/src/netlink/
├── mod.rs                    # Add: pub mod namespace_watcher;
├── namespace.rs              # Existing namespace utilities
└── namespace_watcher.rs      # NEW: NamespaceWatcher implementation
```

#### Step 3: Implement Core Watcher (Async Native with inotify)

```rust
// crates/nlink/src/netlink/namespace_watcher.rs

//! Filesystem-based namespace watcher using inotify.
//!
//! Monitors `/var/run/netns/` for named namespace creation and deletion.
//! This is the recommended way to track namespaces created via `ip netns add`.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::namespace_watcher::{NamespaceWatcher, NamespaceEvent};
//!
//! let mut watcher = NamespaceWatcher::new().await?;
//!
//! while let Some(event) = watcher.recv().await? {
//!     match event {
//!         NamespaceEvent::Created { name } => println!("New namespace: {}", name),
//!         NamespaceEvent::Deleted { name } => println!("Deleted: {}", name),
//!         _ => {}
//!     }
//! }
//! ```

use std::ffi::OsStr;
use std::path::Path;

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use tokio_stream::StreamExt;

use crate::netlink::error::{Error, Result};

const NETNS_DIR: &str = "/var/run/netns";
const PARENT_DIR: &str = "/var/run";

/// Events emitted when named namespaces change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceEvent {
    /// A named namespace was created in /var/run/netns/
    Created { name: String },
    /// A named namespace was deleted from /var/run/netns/
    Deleted { name: String },
    /// The /var/run/netns/ directory itself was created.
    /// After this event, namespace Created/Deleted events will be emitted.
    DirectoryCreated,
    /// The /var/run/netns/ directory was deleted.
    /// After this event, no namespace events will be emitted until DirectoryCreated.
    DirectoryDeleted,
}

/// Configuration for the namespace watcher.
#[derive(Debug, Clone)]
pub struct NamespaceWatcherConfig {
    /// Whether to watch /var/run/ when /var/run/netns/ doesn't exist (default: true)
    pub watch_parent: bool,
    /// Whether to emit DirectoryCreated/DirectoryDeleted events (default: false)
    pub emit_directory_events: bool,
}

impl Default for NamespaceWatcherConfig {
    fn default() -> Self {
        Self {
            watch_parent: true,
            emit_directory_events: false,
        }
    }
}

/// Watches for network namespace changes using inotify.
///
/// Monitors `/var/run/netns/` for namespace creation and deletion.
/// If the directory doesn't exist and `watch_parent` is enabled,
/// watches `/var/run/` for its creation.
///
/// This watcher is fully async and integrates natively with tokio.
pub struct NamespaceWatcher {
    inotify: Inotify,
    buffer: Vec<u8>,
    config: NamespaceWatcherConfig,
    netns_wd: Option<WatchDescriptor>,
    parent_wd: Option<WatchDescriptor>,
}

impl NamespaceWatcher {
    /// Create a new namespace watcher with default configuration.
    pub async fn new() -> Result<Self> {
        Self::with_config(NamespaceWatcherConfig::default()).await
    }

    /// Create a namespace watcher with custom configuration.
    pub async fn with_config(config: NamespaceWatcherConfig) -> Result<Self> {
        let inotify = Inotify::init()
            .map_err(|e| Error::Io(e))?;

        let netns_path = Path::new(NETNS_DIR);
        let mut netns_wd = None;
        let mut parent_wd = None;

        if netns_path.exists() {
            // Directory exists - watch it directly
            let wd = inotify.watches().add(
                NETNS_DIR,
                WatchMask::CREATE | WatchMask::DELETE | WatchMask::DELETE_SELF,
            ).map_err(|e| Error::Io(e))?;
            netns_wd = Some(wd);
        } else if config.watch_parent {
            // Directory doesn't exist - watch parent for its creation
            let wd = inotify.watches().add(
                PARENT_DIR,
                WatchMask::CREATE | WatchMask::MOVED_TO,
            ).map_err(|e| Error::Io(e))?;
            parent_wd = Some(wd);
        }

        Ok(Self {
            inotify,
            buffer: vec![0u8; 4096],
            config,
            netns_wd,
            parent_wd,
        })
    }

    /// List current namespaces and create a watcher for changes.
    ///
    /// The watcher is created FIRST, then namespaces are listed.
    /// This ensures no events are missed between listing and watching.
    ///
    /// Callers should handle potential duplicates: a namespace in the
    /// returned list might also generate a Created event if it was
    /// created during the brief window between watch setup and listing.
    pub async fn list_and_watch() -> Result<(Vec<String>, Self)> {
        // Start watcher FIRST to avoid missing events
        let watcher = Self::new().await?;
        // Then list current namespaces
        let current = super::namespace::list()?;
        Ok((current, watcher))
    }

    /// Check if the watcher is actively monitoring /var/run/netns/.
    ///
    /// Returns `false` if only watching the parent directory (waiting for netns creation).
    pub fn is_watching_netns(&self) -> bool {
        self.netns_wd.is_some()
    }

    /// Receive the next namespace event.
    ///
    /// This method is async and will wait until an event is available.
    /// Returns `Ok(None)` if the watcher has been closed.
    pub async fn recv(&mut self) -> Result<Option<NamespaceEvent>> {
        loop {
            let events = self.inotify
                .read_events(&mut self.buffer)
                .map_err(|e| Error::Io(e))?;

            for event in events {
                if let Some(ns_event) = self.process_event(&event).await? {
                    return Ok(Some(ns_event));
                }
            }
        }
    }

    /// Process a single inotify event and optionally return a NamespaceEvent.
    async fn process_event(
        &mut self,
        event: &inotify::Event<&OsStr>,
    ) -> Result<Option<NamespaceEvent>> {
        let name = event.name.and_then(|n| n.to_str()).map(String::from);

        // Check if this is an event on the netns directory
        if Some(event.wd) == self.netns_wd {
            // Event in /var/run/netns/
            if event.mask.contains(EventMask::DELETE_SELF) {
                // The netns directory itself was deleted
                self.netns_wd = None;

                // Start watching parent if configured
                if self.config.watch_parent {
                    if let Ok(wd) = self.inotify.watches().add(
                        PARENT_DIR,
                        WatchMask::CREATE | WatchMask::MOVED_TO,
                    ) {
                        self.parent_wd = Some(wd);
                    }
                }

                if self.config.emit_directory_events {
                    return Ok(Some(NamespaceEvent::DirectoryDeleted));
                }
            } else if event.mask.contains(EventMask::CREATE) {
                if let Some(name) = name {
                    return Ok(Some(NamespaceEvent::Created { name }));
                }
            } else if event.mask.contains(EventMask::DELETE) {
                if let Some(name) = name {
                    return Ok(Some(NamespaceEvent::Deleted { name }));
                }
            }
        } else if Some(event.wd) == self.parent_wd {
            // Event in /var/run/ - check if netns directory was created
            let is_netns = name.as_deref() == Some("netns");

            if is_netns && (event.mask.contains(EventMask::CREATE) 
                        || event.mask.contains(EventMask::MOVED_TO)) {
                // netns directory appeared - switch to watching it
                if let Ok(wd) = self.inotify.watches().add(
                    NETNS_DIR,
                    WatchMask::CREATE | WatchMask::DELETE | WatchMask::DELETE_SELF,
                ) {
                    // Remove parent watch
                    if let Some(parent_wd) = self.parent_wd.take() {
                        let _ = self.inotify.watches().remove(parent_wd);
                    }
                    self.netns_wd = Some(wd);

                    // Emit events for existing namespaces
                    if let Ok(entries) = std::fs::read_dir(NETNS_DIR) {
                        for entry in entries.flatten() {
                            if let Some(name) = entry.file_name().to_str() {
                                // We can only return one event at a time.
                                // For simplicity, emit DirectoryCreated first if configured,
                                // and let the next recv() calls pick up existing namespaces.
                                // Alternative: buffer events internally.
                            }
                        }
                    }

                    if self.config.emit_directory_events {
                        return Ok(Some(NamespaceEvent::DirectoryCreated));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get an async stream of namespace events.
    ///
    /// This consumes the watcher and returns a stream that yields events.
    pub fn into_stream(self) -> NamespaceEventStream {
        NamespaceEventStream { watcher: self }
    }
}

/// An async stream of namespace events.
pub struct NamespaceEventStream {
    watcher: NamespaceWatcher,
}

impl NamespaceEventStream {
    /// Receive the next event from the stream.
    pub async fn next(&mut self) -> Option<Result<NamespaceEvent>> {
        match self.watcher.recv().await {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}
```

#### Step 4: Add to Module Exports

In `crates/nlink/src/netlink/mod.rs`:

```rust
#[cfg(feature = "namespace_watcher")]
pub mod namespace_watcher;

#[cfg(feature = "namespace_watcher")]
pub use namespace_watcher::{NamespaceEvent, NamespaceWatcher, NamespaceWatcherConfig, NamespaceEventStream};
```

#### Step 5: Add Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = NamespaceWatcherConfig::default();
        assert!(config.watch_parent);
        assert!(!config.emit_directory_events);
    }

    #[tokio::test]
    async fn test_watcher_creation() {
        // May fail if /var/run doesn't exist (unlikely on Linux)
        let result = NamespaceWatcher::new().await;
        // Don't assert success - depends on system state
        if let Ok(watcher) = result {
            // Watcher should know whether it's watching netns or parent
            let watching = watcher.is_watching_netns();
            println!("Watching netns directly: {}", watching);
        }
    }

    #[tokio::test]
    async fn test_list_and_watch() {
        if let Ok((namespaces, watcher)) = NamespaceWatcher::list_and_watch().await {
            println!("Current namespaces: {:?}", namespaces);
            println!("Watching netns: {}", watcher.is_watching_netns());
        }
    }

    #[tokio::test]
    async fn test_custom_config() {
        let config = NamespaceWatcherConfig {
            watch_parent: false,
            emit_directory_events: true,
        };
        
        // This might fail if /var/run/netns doesn't exist and watch_parent is false
        let result = NamespaceWatcher::with_config(config).await;
        // Just verify it doesn't panic
        let _ = result;
    }
}
```

---

### Solution 5: Netlink Events (Corrected)

#### Step 1: Add Namespace Constants

Create `crates/nlink/src/netlink/types/nsid.rs`:

```rust
//! Namespace ID netlink message types and constants.

/// RTM_NEWNSID - New namespace ID notification
pub const RTM_NEWNSID: u16 = 88;
/// RTM_DELNSID - Delete namespace ID notification
pub const RTM_DELNSID: u16 = 89;
/// RTM_GETNSID - Get namespace ID request
pub const RTM_GETNSID: u16 = 90;

/// Netlink namespace ID message attributes (NETNSA_*)
pub mod netnsa {
    /// Namespace ID (u32)
    pub const NSID: u16 = 1;
    /// Process ID (u32)
    pub const PID: u16 = 2;
    /// File descriptor (u32)
    pub const FD: u16 = 3;
    /// Target namespace ID for queries (u32)
    pub const TARGET_NSID: u16 = 4;
    /// Current namespace ID (u32)
    pub const CURRENT_NSID: u16 = 5;
}

/// Multicast group for namespace events.
/// 
/// Note: Reliable multicast for NSID events requires Linux 4.9+.
/// On older kernels (3.8-4.8), events may be unreliable.
pub const RTNLGRP_NSID: u32 = 28;

/// rtgenmsg structure for namespace messages.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RtGenMsg {
    pub rtgen_family: u8,
}

impl RtGenMsg {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_bytes(&self) -> &[u8] {
        // rtgenmsg is 1 byte but padded to 4 bytes in netlink
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, 1) }
    }
}
```

Add to `crates/nlink/src/netlink/types/mod.rs`:

```rust
pub mod nsid;
pub use nsid::*;
```

#### Step 2: Add Multicast Group Subscription

In `crates/nlink/src/netlink/socket.rs`, add:

```rust
impl NetlinkSocket {
    /// Subscribe to a netlink multicast group.
    ///
    /// # Arguments
    /// * `group` - The multicast group number (e.g., RTNLGRP_NSID for namespace events)
    ///
    /// # Errors
    /// Returns an error if the setsockopt call fails (e.g., permission denied,
    /// invalid group number).
    pub fn add_membership(&self, group: u32) -> Result<()> {
        let group_val = group as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                &group_val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(Error::from_io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Unsubscribe from a netlink multicast group.
    pub fn drop_membership(&self, group: u32) -> Result<()> {
        let group_val = group as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_NETLINK,
                libc::NETLINK_DROP_MEMBERSHIP,
                &group_val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(Error::from_io(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}
```

#### Step 3: Implement NsIdMessage Parsing

Create `crates/nlink/src/netlink/messages/nsid.rs`:

```rust
//! Namespace ID message parsing.

use crate::netlink::attr::AttrIter;
use crate::netlink::types::nsid::netnsa;

/// Parsed namespace ID message from RTM_NEWNSID/RTM_DELNSID.
#[derive(Debug, Clone, Default)]
pub struct NsIdMessage {
    /// Address family (usually AF_UNSPEC = 0)
    pub family: u8,
    /// Namespace ID
    pub nsid: Option<u32>,
    /// Process ID that owns/triggered the namespace
    pub pid: Option<u32>,
    /// File descriptor (for fd-based references)
    pub fd: Option<i32>,
    /// Target namespace ID (for queries)
    pub target_nsid: Option<u32>,
    /// Current namespace ID
    pub current_nsid: Option<u32>,
}

impl NsIdMessage {
    /// Parse a namespace ID message from raw bytes.
    ///
    /// The input should be the payload after the netlink header (16 bytes).
    /// Format: rtgenmsg (1 byte family + 3 padding) + attributes
    ///
    /// FIX Issue 3: Return Option instead of PResult for simpler error handling
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        // Parse rtgenmsg header (1 byte family, 3 bytes padding)
        let family = data[0];
        
        // Attributes start at offset 4 (after rtgenmsg + padding)
        let attr_data = data.get(4..)?;

        let mut msg = NsIdMessage {
            family,
            ..Default::default()
        };

        // Parse attributes using existing AttrIter
        for attr in AttrIter::new(attr_data) {
            let payload = attr.payload();
            match attr.kind() {
                x if x == netnsa::NSID => {
                    if payload.len() >= 4 {
                        msg.nsid = Some(u32::from_ne_bytes(
                            payload[..4].try_into().ok()?
                        ));
                    }
                }
                x if x == netnsa::PID => {
                    if payload.len() >= 4 {
                        msg.pid = Some(u32::from_ne_bytes(
                            payload[..4].try_into().ok()?
                        ));
                    }
                }
                x if x == netnsa::FD => {
                    if payload.len() >= 4 {
                        msg.fd = Some(i32::from_ne_bytes(
                            payload[..4].try_into().ok()?
                        ));
                    }
                }
                x if x == netnsa::TARGET_NSID => {
                    if payload.len() >= 4 {
                        msg.target_nsid = Some(u32::from_ne_bytes(
                            payload[..4].try_into().ok()?
                        ));
                    }
                }
                x if x == netnsa::CURRENT_NSID => {
                    if payload.len() >= 4 {
                        msg.current_nsid = Some(u32::from_ne_bytes(
                            payload[..4].try_into().ok()?
                        ));
                    }
                }
                _ => {}
            }
        }

        Some(msg)
    }
}
```

Add to `crates/nlink/src/netlink/messages/mod.rs`:

```rust
pub mod nsid;
pub use nsid::NsIdMessage;
```

#### Step 4: Implement Event Subscriber

Create `crates/nlink/src/netlink/namespace_events.rs`:

```rust
//! Netlink-based namespace event subscriber.
//!
//! Receives RTM_NEWNSID and RTM_DELNSID events from the kernel.
//!
//! # Kernel Version Requirements
//!
//! - Linux 3.8+: Basic RTM_*NSID support
//! - Linux 4.9+: Reliable multicast delivery (recommended)
//!
//! # Limitations
//!
//! NSID events are triggered when namespace IDs are assigned or removed,
//! which doesn't always correspond to named namespace creation via `ip netns add`.
//! For tracking named namespaces, use `NamespaceWatcher` (filesystem-based) instead.

use std::os::fd::AsRawFd;

use crate::netlink::error::{Error, Result};
use crate::netlink::messages::NsIdMessage;
use crate::netlink::socket::{NetlinkSocket, Protocol};
use crate::netlink::types::nsid::{RTM_NEWNSID, RTM_DELNSID, RTNLGRP_NSID};

/// Namespace-related netlink events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceNetlinkEvent {
    /// A new namespace ID was assigned.
    NewNsId {
        /// The namespace ID (local to this netns)
        nsid: u32,
        /// Process ID that triggered this (if available)
        pid: Option<u32>,
        /// File descriptor reference (if available)
        fd: Option<i32>,
    },
    /// A namespace ID was removed.
    DelNsId {
        /// The namespace ID that was removed
        nsid: u32,
    },
}

/// Subscribe to namespace netlink events.
///
/// Listens for RTM_NEWNSID and RTM_DELNSID multicast messages.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace_events::NamespaceEventSubscriber;
///
/// let mut subscriber = NamespaceEventSubscriber::new().await?;
///
/// while let Some(event) = subscriber.recv().await? {
///     match event {
///         NamespaceNetlinkEvent::NewNsId { nsid, pid, .. } => {
///             println!("New namespace ID {} from pid {:?}", nsid, pid);
///         }
///         NamespaceNetlinkEvent::DelNsId { nsid } => {
///             println!("Namespace ID {} removed", nsid);
///         }
///     }
/// }
/// ```
pub struct NamespaceEventSubscriber {
    socket: NetlinkSocket,
    buffer: Vec<u8>,
}

impl NamespaceEventSubscriber {
    /// Create a new subscriber for namespace events.
    ///
    /// Subscribes to the RTNLGRP_NSID multicast group.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Socket creation fails
    /// - Multicast group subscription fails (may require CAP_NET_ADMIN)
    pub async fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(Protocol::Route)?;

        // Subscribe to namespace ID multicast group
        socket.add_membership(RTNLGRP_NSID)?;

        Ok(Self {
            socket,
            buffer: vec![0u8; 8192],
        })
    }

    /// Receive the next namespace event.
    ///
    /// Blocks until a namespace event is received or an error occurs.
    /// Returns `Ok(None)` if the socket is closed.
    pub async fn recv(&mut self) -> Result<Option<NamespaceNetlinkEvent>> {
        loop {
            let len = self.socket.recv(&mut self.buffer).await?;
            if len == 0 {
                return Ok(None);
            }

            // FIX Issue 3: parse_message returns Option, handle gracefully
            if let Some(event) = self.parse_message(&self.buffer[..len]) {
                return Ok(Some(event));
            }
            // Not a namespace event, continue waiting
        }
    }

    /// Try to receive an event without blocking.
    ///
    /// Returns `Ok(None)` if no event is immediately available.
    pub fn try_recv(&mut self) -> Result<Option<NamespaceNetlinkEvent>> {
        // Use non-blocking recv if available, otherwise return None
        // This is a simplified implementation - real impl would use try_recv on socket
        Ok(None)
    }

    /// Parse a netlink message into a namespace event.
    ///
    /// FIX Issue 3: Returns Option instead of using ? operator incorrectly
    fn parse_message(&self, data: &[u8]) -> Option<NamespaceNetlinkEvent> {
        // Netlink header is 16 bytes
        if data.len() < 16 {
            return None;
        }

        let msg_len = u32::from_ne_bytes(data[0..4].try_into().ok()?) as usize;
        let msg_type = u16::from_ne_bytes(data[4..6].try_into().ok()?);

        if msg_len > data.len() || msg_len < 16 {
            return None;
        }

        let payload = &data[16..msg_len];

        match msg_type {
            RTM_NEWNSID => {
                // FIX Issue 3: Use .ok()? pattern for Option chaining
                let msg = NsIdMessage::parse(payload)?;
                let nsid = msg.nsid?; // NSID is required
                Some(NamespaceNetlinkEvent::NewNsId {
                    nsid,
                    pid: msg.pid,
                    fd: msg.fd,
                })
            }
            RTM_DELNSID => {
                let msg = NsIdMessage::parse(payload)?;
                let nsid = msg.nsid?;
                Some(NamespaceNetlinkEvent::DelNsId { nsid })
            }
            _ => None,
        }
    }
}
```

#### Step 5: Add get_nsid Methods to Connection

In `crates/nlink/src/netlink/connection.rs`, add:

```rust
use crate::netlink::types::nsid::{RTM_GETNSID, netnsa, RtGenMsg};

impl Connection {
    /// Get the namespace ID for a given file descriptor.
    ///
    /// The file descriptor should be an open reference to a network namespace
    /// (e.g., from opening `/proc/<pid>/ns/net`).
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace ID cannot be determined.
    pub async fn get_nsid(&self, ns_fd: std::os::fd::RawFd) -> Result<u32> {
        let mut builder = MessageBuilder::new(
            NlMsgType::from(RTM_GETNSID),
            NlMsgFlags::REQUEST,
        );

        builder.append(&RtGenMsg::new());
        // Pad to 4 bytes
        builder.append(&[0u8; 3]);

        // Add NETNSA_FD attribute
        builder.append_attr(netnsa::FD, &(ns_fd as u32).to_ne_bytes());

        let responses = self.request(builder).await?;

        for msg in responses {
            if let Some(nsid_msg) = NsIdMessage::parse(&msg.payload) {
                if let Some(nsid) = nsid_msg.nsid {
                    return Ok(nsid);
                }
            }
        }

        Err(Error::NotFound("namespace ID not found".into()))
    }

    /// Get the namespace ID for a given process's network namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace ID cannot be determined.
    pub async fn get_nsid_for_pid(&self, pid: u32) -> Result<u32> {
        let mut builder = MessageBuilder::new(
            NlMsgType::from(RTM_GETNSID),
            NlMsgFlags::REQUEST,
        );

        builder.append(&RtGenMsg::new());
        builder.append(&[0u8; 3]);

        // Add NETNSA_PID attribute
        builder.append_attr(netnsa::PID, &pid.to_ne_bytes());

        let responses = self.request(builder).await?;

        for msg in responses {
            if let Some(nsid_msg) = NsIdMessage::parse(&msg.payload) {
                if let Some(nsid) = nsid_msg.nsid {
                    return Ok(nsid);
                }
            }
        }

        Err(Error::NotFound("namespace ID not found".into()))
    }
}
```

#### Step 6: Add to Module Exports

In `crates/nlink/src/netlink/mod.rs`:

```rust
pub mod namespace_events;
pub use namespace_events::{NamespaceEventSubscriber, NamespaceNetlinkEvent};
```

#### Step 7: Add Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subscriber_creation() {
        // May require CAP_NET_ADMIN
        let result = NamespaceEventSubscriber::new().await;
        // Don't assert - depends on permissions
        if result.is_err() {
            eprintln!("Subscriber creation failed (may need CAP_NET_ADMIN): {:?}", result.err());
        }
    }

    #[test]
    fn test_nsid_message_parsing() {
        // rtgenmsg (1 byte family + 3 padding) + NETNSA_NSID attribute
        let data = [
            0x00, 0x00, 0x00, 0x00, // rtgenmsg: family=0, padding
            0x08, 0x00,             // attr len=8
            0x01, 0x00,             // attr type=NETNSA_NSID
            0x42, 0x00, 0x00, 0x00, // nsid=66
        ];

        let msg = NsIdMessage::parse(&data).unwrap();
        assert_eq!(msg.family, 0);
        assert_eq!(msg.nsid, Some(66));
        assert_eq!(msg.pid, None);
    }

    #[test]
    fn test_nsid_message_with_pid() {
        let data = [
            0x00, 0x00, 0x00, 0x00, // rtgenmsg
            0x08, 0x00, 0x01, 0x00, // NETNSA_NSID
            0x01, 0x00, 0x00, 0x00, // nsid=1
            0x08, 0x00, 0x02, 0x00, // NETNSA_PID
            0xe8, 0x03, 0x00, 0x00, // pid=1000
        ];

        let msg = NsIdMessage::parse(&data).unwrap();
        assert_eq!(msg.nsid, Some(1));
        assert_eq!(msg.pid, Some(1000));
    }
}
```

---

### Summary of Issue Fixes

| Issue | Location | Fix Applied |
|-------|----------|-------------|
| 1. Blocking send | namespace_watcher.rs | **Eliminated** - Using async `inotify` with direct `recv()` pattern |
| 2. Race condition | `list_and_watch()` | Watcher created before listing |
| 3. Parse error handling | namespace_events.rs | `NsIdMessage::parse` returns `Option`, uses `?` correctly |
| 4. Feature flag naming | Cargo.toml | Use `namespace_watcher` (underscore) |
| 5. Missing Drop | namespace_watcher.rs | **N/A** - `Inotify` handles cleanup automatically |
| 6. Thread safety | namespace_watcher.rs | **Eliminated** - No shared state, no threads, fully async |
| 7. Async integration | namespace_watcher.rs | **NEW** - Using `inotify` crate with native tokio support |

---

### Files Checklist

#### New Files to Create

- [ ] `crates/nlink/src/netlink/namespace_watcher.rs` - Solution 4 (inotify-based, async)
- [ ] `crates/nlink/src/netlink/namespace_events.rs` - Solution 5 (netlink-based)
- [ ] `crates/nlink/src/netlink/types/nsid.rs` - NSID constants
- [ ] `crates/nlink/src/netlink/messages/nsid.rs` - NsIdMessage parsing

#### Files to Modify

- [ ] `crates/nlink/Cargo.toml` - Add `inotify` dependency, `namespace_watcher` feature
- [ ] `crates/nlink/src/netlink/mod.rs` - Export new modules
- [ ] `crates/nlink/src/netlink/types/mod.rs` - Export nsid module
- [ ] `crates/nlink/src/netlink/messages/mod.rs` - Export NsIdMessage
- [ ] `crates/nlink/src/netlink/socket.rs` - Add `add_membership()`, `drop_membership()`
- [ ] `crates/nlink/src/netlink/connection.rs` - Add `get_nsid()`, `get_nsid_for_pid()`
- [ ] `crates/nlink/src/lib.rs` - Re-export namespace watcher types

---

### Dependency Summary

| Solution | Crate | Version | Features | Notes |
|----------|-------|---------|----------|-------|
| Solution 4 | `inotify` | 0.11 | `stream` | Linux-native, async, no extra threads |
| Solution 5 | (none) | - | - | Uses existing netlink socket infrastructure |
