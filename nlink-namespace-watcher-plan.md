# nlink Namespace Watcher Implementation Plan

This document outlines the implementation plan for adding namespace watching capabilities to nlink. Two approaches are proposed: filesystem-based watching (Solution 4) and netlink-based events (Solution 5).

---

## Solution 4: Filesystem-based NamespaceWatcher

### Overview

Add a `NamespaceWatcher` struct that uses inotify to monitor `/var/run/netns/` for namespace changes, handling the directory lifecycle gracefully.

### API Design

```rust
// nlink/src/netlink/namespace_watcher.rs

use tokio::sync::mpsc;

/// Events emitted when named namespaces change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceEvent {
    /// A named namespace was created in /var/run/netns/
    Created { name: String },
    /// A named namespace was deleted from /var/run/netns/
    Deleted { name: String },
    /// The /var/run/netns/ directory itself was created
    /// (useful for knowing inotify is now active)
    DirectoryCreated,
    /// The /var/run/netns/ directory was deleted
    /// (watcher falls back to parent monitoring)
    DirectoryDeleted,
}

/// Configuration for the namespace watcher.
#[derive(Debug, Clone)]
pub struct NamespaceWatcherConfig {
    /// Channel buffer size for events (default: 100)
    pub buffer_size: usize,
    /// Whether to watch /var/run/ when /var/run/netns/ doesn't exist (default: true)
    pub watch_parent: bool,
    /// Whether to emit DirectoryCreated/DirectoryDeleted events (default: false)
    pub emit_directory_events: bool,
}

impl Default for NamespaceWatcherConfig {
    fn default() -> Self {
        Self {
            buffer_size: 100,
            watch_parent: true,
            emit_directory_events: false,
        }
    }
}

/// Watches for network namespace changes.
///
/// Monitors `/var/run/netns/` for namespace creation and deletion.
/// If the directory doesn't exist, optionally watches `/var/run/` for its creation.
pub struct NamespaceWatcher {
    // Internal state...
}

impl NamespaceWatcher {
    /// Create a new namespace watcher with default configuration.
    ///
    /// Returns the watcher and a receiver for namespace events.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::namespace_watcher::{NamespaceWatcher, NamespaceEvent};
    ///
    /// let (watcher, mut events) = NamespaceWatcher::new()?;
    ///
    /// // Process events
    /// while let Some(event) = events.recv().await {
    ///     match event {
    ///         NamespaceEvent::Created { name } => println!("New namespace: {}", name),
    ///         NamespaceEvent::Deleted { name } => println!("Deleted namespace: {}", name),
    ///         _ => {}
    ///     }
    /// }
    /// ```
    pub fn new() -> Result<(Self, mpsc::Receiver<NamespaceEvent>)>;

    /// Create a namespace watcher with custom configuration.
    pub fn with_config(config: NamespaceWatcherConfig) -> Result<(Self, mpsc::Receiver<NamespaceEvent>)>;

    /// List current namespaces and start watching for changes.
    ///
    /// This is useful for initial synchronization - get the current state
    /// and then watch for changes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (current, watcher, events) = NamespaceWatcher::list_and_watch()?;
    /// println!("Current namespaces: {:?}", current);
    /// // Now process events for changes...
    /// ```
    pub fn list_and_watch() -> Result<(Vec<String>, Self, mpsc::Receiver<NamespaceEvent>)>;

    /// Check if the watcher is actively monitoring /var/run/netns/.
    ///
    /// Returns `false` if only watching the parent directory waiting for netns creation.
    pub fn is_watching_netns(&self) -> bool;

    /// Stop the watcher and release resources.
    pub fn stop(self);
}
```

### Implementation Steps

#### Step 1: Add Dependencies

In `nlink/Cargo.toml`:

```toml
[dependencies]
notify = { version = "6.1", default-features = false, features = ["macos_fsevent"] }

[features]
default = ["namespace-watcher"]
namespace-watcher = ["notify"]
```

Make it optional so users who don't need it can avoid the dependency.

#### Step 2: Create Module Structure

```
nlink/src/netlink/
├── mod.rs                    # Add: pub mod namespace_watcher;
├── namespace.rs              # Existing namespace utilities
└── namespace_watcher.rs      # NEW: NamespaceWatcher implementation
```

#### Step 3: Implement Core Watcher

```rust
// nlink/src/netlink/namespace_watcher.rs

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use super::error::Result;

const NETNS_DIR: &str = "/var/run/netns";
const PARENT_DIR: &str = "/var/run";

pub struct NamespaceWatcher {
    state: Arc<Mutex<WatcherState>>,
    config: NamespaceWatcherConfig,
}

struct WatcherState {
    netns_watcher: Option<RecommendedWatcher>,
    parent_watcher: Option<RecommendedWatcher>,
    watching_netns: bool,
}

impl NamespaceWatcher {
    pub fn new() -> Result<(Self, mpsc::Receiver<NamespaceEvent>)> {
        Self::with_config(NamespaceWatcherConfig::default())
    }

    pub fn with_config(config: NamespaceWatcherConfig) -> Result<(Self, mpsc::Receiver<NamespaceEvent>)> {
        let (tx, rx) = mpsc::channel(config.buffer_size);
        
        let state = Arc::new(Mutex::new(WatcherState {
            netns_watcher: None,
            parent_watcher: None,
            watching_netns: false,
        }));

        let netns_path = Path::new(NETNS_DIR);
        
        if netns_path.exists() {
            // Directory exists - watch it directly
            let watcher = Self::create_netns_watcher(tx.clone(), state.clone(), &config)?;
            state.lock().unwrap().netns_watcher = Some(watcher);
            state.lock().unwrap().watching_netns = true;
        } else if config.watch_parent {
            // Directory doesn't exist - watch parent for its creation
            let watcher = Self::create_parent_watcher(tx.clone(), state.clone(), &config)?;
            state.lock().unwrap().parent_watcher = Some(watcher);
        }

        Ok((Self { state, config }, rx))
    }

    fn create_netns_watcher(
        tx: mpsc::Sender<NamespaceEvent>,
        state: Arc<Mutex<WatcherState>>,
        config: &NamespaceWatcherConfig,
    ) -> Result<RecommendedWatcher> {
        let emit_dir_events = config.emit_directory_events;
        
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                Self::handle_netns_event(&event, &tx, &state, emit_dir_events);
            }
        })?;

        watcher.watch(Path::new(NETNS_DIR), RecursiveMode::NonRecursive)?;
        Ok(watcher)
    }

    fn create_parent_watcher(
        tx: mpsc::Sender<NamespaceEvent>,
        state: Arc<Mutex<WatcherState>>,
        config: &NamespaceWatcherConfig,
    ) -> Result<RecommendedWatcher> {
        let config_clone = config.clone();
        let tx_clone = tx.clone();
        
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                Self::handle_parent_event(&event, &tx_clone, &state, &config_clone);
            }
        })?;

        watcher.watch(Path::new(PARENT_DIR), RecursiveMode::NonRecursive)?;
        Ok(watcher)
    }

    fn handle_netns_event(
        event: &Event,
        tx: &mpsc::Sender<NamespaceEvent>,
        _state: &Arc<Mutex<WatcherState>>,
        emit_dir_events: bool,
    ) {
        let get_name = |paths: &[PathBuf]| -> Option<String> {
            paths.first()?.file_name()?.to_str().map(String::from)
        };

        match &event.kind {
            EventKind::Create(_) => {
                if let Some(name) = get_name(&event.paths) {
                    let _ = tx.blocking_send(NamespaceEvent::Created { name });
                }
            }
            EventKind::Remove(_) => {
                if let Some(name) = get_name(&event.paths) {
                    // Check if it's the directory itself being removed
                    if event.paths.first().map(|p| p.as_path()) == Some(Path::new(NETNS_DIR)) {
                        if emit_dir_events {
                            let _ = tx.blocking_send(NamespaceEvent::DirectoryDeleted);
                        }
                        // TODO: Switch back to parent watcher
                    } else {
                        let _ = tx.blocking_send(NamespaceEvent::Deleted { name });
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_parent_event(
        event: &Event,
        tx: &mpsc::Sender<NamespaceEvent>,
        state: &Arc<Mutex<WatcherState>>,
        config: &NamespaceWatcherConfig,
    ) {
        // Check if /var/run/netns was created
        if matches!(event.kind, EventKind::Create(_)) {
            let is_netns = event.paths.iter().any(|p| {
                p.file_name().map(|n| n == "netns").unwrap_or(false)
            });
            
            if is_netns && Path::new(NETNS_DIR).exists() {
                // Switch to watching netns directory
                if let Ok(watcher) = Self::create_netns_watcher(tx.clone(), state.clone(), config) {
                    let mut state_guard = state.lock().unwrap();
                    state_guard.netns_watcher = Some(watcher);
                    state_guard.parent_watcher = None; // Stop parent watcher
                    state_guard.watching_netns = true;
                    
                    if config.emit_directory_events {
                        let _ = tx.blocking_send(NamespaceEvent::DirectoryCreated);
                    }
                    
                    // Emit Created events for any namespaces that already exist
                    if let Ok(entries) = std::fs::read_dir(NETNS_DIR) {
                        for entry in entries.flatten() {
                            if let Some(name) = entry.file_name().to_str() {
                                let _ = tx.blocking_send(NamespaceEvent::Created { 
                                    name: name.to_string() 
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn is_watching_netns(&self) -> bool {
        self.state.lock().unwrap().watching_netns
    }

    pub fn list_and_watch() -> Result<(Vec<String>, Self, mpsc::Receiver<NamespaceEvent>)> {
        let current = super::list()?;
        let (watcher, rx) = Self::new()?;
        Ok((current, watcher, rx))
    }

    pub fn stop(self) {
        // Watchers are dropped automatically
        drop(self.state);
    }
}
```

#### Step 4: Add to Module Exports

In `nlink/src/netlink/mod.rs`:

```rust
#[cfg(feature = "namespace-watcher")]
pub mod namespace_watcher;

#[cfg(feature = "namespace-watcher")]
pub use namespace_watcher::{NamespaceEvent, NamespaceWatcher, NamespaceWatcherConfig};
```

#### Step 5: Add Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_watcher_creation() {
        let result = NamespaceWatcher::new();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_and_watch() {
        let result = NamespaceWatcher::list_and_watch();
        assert!(result.is_ok());
        let (namespaces, _watcher, _rx) = result.unwrap();
        // Should return current namespaces (may be empty)
        println!("Current namespaces: {:?}", namespaces);
    }

    #[tokio::test]
    async fn test_watcher_config() {
        let config = NamespaceWatcherConfig {
            buffer_size: 50,
            watch_parent: true,
            emit_directory_events: true,
        };
        let result = NamespaceWatcher::with_config(config);
        assert!(result.is_ok());
    }
}
```

### Edge Cases to Handle

1. **Directory created between check and watch**: Use a retry loop
2. **Directory deleted while watching**: Switch back to parent watcher
3. **Rapid create/delete**: Ensure events are ordered correctly
4. **Permission errors**: Return appropriate errors
5. **Symlinks in netns directory**: Follow or ignore based on config

---

## Solution 5: Netlink-based Namespace Events

### Overview

Use `RTM_NEWNSID` and `RTM_DELNSID` netlink messages to receive kernel notifications about namespace changes. This is the most robust solution as it doesn't depend on filesystem watching.

### Background: Netlink Namespace ID Messages

Linux kernel (3.8+) supports namespace ID assignment and tracking via netlink:

- `RTM_NEWNSID` - Sent when a namespace ID is assigned
- `RTM_DELNSID` - Sent when a namespace ID is removed
- `RTM_GETNSID` - Query namespace ID

These are part of the `NETLINK_ROUTE` protocol family.

### API Design

```rust
// nlink/src/netlink/namespace_events.rs

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
pub struct NamespaceEventSubscriber {
    // ...
}

impl NamespaceEventSubscriber {
    /// Create a new subscriber for namespace events.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::namespace_events::NamespaceEventSubscriber;
    ///
    /// let mut subscriber = NamespaceEventSubscriber::new()?;
    ///
    /// while let Some(event) = subscriber.recv().await {
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
    pub async fn new() -> Result<Self>;

    /// Receive the next namespace event.
    pub async fn recv(&mut self) -> Option<NamespaceNetlinkEvent>;

    /// Try to receive an event without blocking.
    pub fn try_recv(&mut self) -> Option<NamespaceNetlinkEvent>;
}

// Integration with Connection
impl Connection {
    /// Subscribe to namespace ID events on this connection.
    ///
    /// The connection must be created with appropriate multicast group subscriptions.
    pub async fn subscribe_namespace_events(&mut self) -> Result<()>;
}
```

### Implementation Steps

#### Step 1: Define Netlink Constants

```rust
// nlink/src/netlink/types/namespace.rs (NEW FILE)

/// RTM_NEWNSID - New namespace ID notification
pub const RTM_NEWNSID: u16 = 88;
/// RTM_DELNSID - Delete namespace ID notification  
pub const RTM_DELNSID: u16 = 89;
/// RTM_GETNSID - Get namespace ID request
pub const RTM_GETNSID: u16 = 90;

/// Netlink namespace ID message attributes
pub mod netnsa {
    /// Namespace ID (u32)
    pub const NETNSA_NSID: u16 = 1;
    /// Process ID (u32)
    pub const NETNSA_PID: u16 = 2;
    /// File descriptor (u32)
    pub const NETNSA_FD: u16 = 3;
    /// Target namespace ID for queries (u32)
    pub const NETNSA_TARGET_NSID: u16 = 4;
    /// Current namespace ID (u32)
    pub const NETNSA_CURRENT_NSID: u16 = 5;
}

/// Multicast group for namespace events
pub const RTNLGRP_NSID: u32 = 28;

/// rtgenmsg structure for namespace messages
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RtGenMsg {
    pub rtgen_family: u8,
}
```

#### Step 2: Add Multicast Group Subscription

```rust
// Extend nlink/src/netlink/socket.rs

impl NetlinkSocket {
    /// Subscribe to a netlink multicast group.
    pub fn add_membership(&self, group: u32) -> Result<()> {
        let group_val = group as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                &group_val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}
```

#### Step 3: Implement Message Parsing

```rust
// nlink/src/netlink/messages/namespace.rs (NEW FILE)

use winnow::prelude::*;
use crate::netlink::parse::{FromNetlink, PResult};

/// Parsed namespace ID message.
#[derive(Debug, Clone, Default)]
pub struct NsIdMessage {
    /// Address family (usually AF_UNSPEC)
    pub family: u8,
    /// Namespace ID
    pub nsid: Option<u32>,
    /// Process ID that owns the namespace
    pub pid: Option<u32>,
    /// File descriptor (for fd-based references)
    pub fd: Option<i32>,
    /// Target namespace ID (for queries)
    pub target_nsid: Option<u32>,
}

impl FromNetlink for NsIdMessage {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse rtgenmsg header (1 byte family + padding)
        let family = winnow::binary::le_u8.parse_next(input)?;
        // Skip padding (3 bytes to align to 4)
        let _ = winnow::token::take(3usize).parse_next(input)?;
        
        let mut msg = NsIdMessage {
            family,
            ..Default::default()
        };

        // Parse attributes
        while !input.is_empty() {
            let attr_len = winnow::binary::le_u16.parse_next(input)?;
            let attr_type = winnow::binary::le_u16.parse_next(input)?;
            
            let payload_len = (attr_len as usize).saturating_sub(4);
            let payload = winnow::token::take(payload_len).parse_next(input)?;
            
            // Align to 4 bytes
            let padding = (4 - (attr_len as usize % 4)) % 4;
            if padding > 0 && !input.is_empty() {
                let _ = winnow::token::take(padding.min(input.len())).parse_next(input)?;
            }

            match attr_type {
                super::super::types::namespace::netnsa::NETNSA_NSID => {
                    if payload.len() >= 4 {
                        msg.nsid = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                super::super::types::namespace::netnsa::NETNSA_PID => {
                    if payload.len() >= 4 {
                        msg.pid = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                super::super::types::namespace::netnsa::NETNSA_FD => {
                    if payload.len() >= 4 {
                        msg.fd = Some(i32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                _ => {}
            }
        }

        Ok(msg)
    }
}
```

#### Step 4: Implement Event Subscriber

```rust
// nlink/src/netlink/namespace_events.rs

use tokio::sync::mpsc;
use super::connection::Connection;
use super::socket::{NetlinkSocket, Protocol};
use super::types::namespace::{RTM_NEWNSID, RTM_DELNSID, RTNLGRP_NSID};
use super::messages::namespace::NsIdMessage;
use super::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceNetlinkEvent {
    NewNsId {
        nsid: u32,
        pid: Option<u32>,
        fd: Option<i32>,
    },
    DelNsId {
        nsid: u32,
    },
}

pub struct NamespaceEventSubscriber {
    socket: NetlinkSocket,
    buffer: Vec<u8>,
}

impl NamespaceEventSubscriber {
    pub async fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(Protocol::Route)?;
        
        // Subscribe to namespace ID multicast group
        socket.add_membership(RTNLGRP_NSID)?;
        
        Ok(Self {
            socket,
            buffer: vec![0u8; 8192],
        })
    }

    pub async fn recv(&mut self) -> Option<NamespaceNetlinkEvent> {
        loop {
            match self.socket.recv(&mut self.buffer).await {
                Ok(len) => {
                    if let Some(event) = self.parse_message(&self.buffer[..len]) {
                        return Some(event);
                    }
                    // Continue if message wasn't a namespace event
                }
                Err(_) => return None,
            }
        }
    }

    fn parse_message(&self, data: &[u8]) -> Option<NamespaceNetlinkEvent> {
        // Parse netlink header
        if data.len() < 16 {
            return None;
        }

        let msg_len = u32::from_ne_bytes(data[0..4].try_into().ok()?) as usize;
        let msg_type = u16::from_ne_bytes(data[4..6].try_into().ok()?);
        
        if msg_len > data.len() {
            return None;
        }

        let payload = &data[16..msg_len];
        
        match msg_type {
            RTM_NEWNSID => {
                let msg = NsIdMessage::parse(&mut &payload[..])?;
                Some(NamespaceNetlinkEvent::NewNsId {
                    nsid: msg.nsid?,
                    pid: msg.pid,
                    fd: msg.fd,
                })
            }
            RTM_DELNSID => {
                let msg = NsIdMessage::parse(&mut &payload[..])?;
                Some(NamespaceNetlinkEvent::DelNsId {
                    nsid: msg.nsid?,
                })
            }
            _ => None,
        }
    }
}
```

#### Step 5: Add Integration with Connection

```rust
// Add to nlink/src/netlink/connection.rs

impl Connection {
    /// Get the namespace ID for a given namespace file descriptor.
    pub async fn get_nsid(&self, ns_fd: RawFd) -> Result<u32> {
        // Build RTM_GETNSID request with NETNSA_FD attribute
        // ...
    }

    /// Get the namespace ID for a given PID's network namespace.
    pub async fn get_nsid_for_pid(&self, pid: u32) -> Result<u32> {
        // Build RTM_GETNSID request with NETNSA_PID attribute
        // ...
    }
}
```

#### Step 6: Add Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subscriber_creation() {
        let result = NamespaceEventSubscriber::new().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore] // Requires namespace operations during test
    async fn test_receive_namespace_event() {
        let mut subscriber = NamespaceEventSubscriber::new().await.unwrap();
        
        // In another thread/process: ip netns add testns
        // Then check for NewNsId event
        
        let event = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            subscriber.recv()
        ).await;
        
        // Verify event received
    }
}
```

### Limitations of Netlink Approach

1. **NSID vs Named Namespaces**: Netlink events are about namespace IDs, not names. To map NSID to `/var/run/netns/` names, you need to:
   - Track which NSIDs correspond to which named namespaces
   - Or combine with filesystem watching for name discovery

2. **Kernel Version**: RTM_*NSID requires Linux 3.8+, but reliable multicast requires 4.9+

3. **Namespace ID Assignment**: NSIDs are only assigned when explicitly requested or when cross-namespace references are made. Simply doing `ip netns add foo` may not generate an event unless something queries the NSID.

### Hybrid Approach (Recommended)

Combine both solutions for maximum robustness:

```rust
/// Unified namespace watcher that uses both filesystem and netlink events.
pub struct UnifiedNamespaceWatcher {
    fs_watcher: NamespaceWatcher,
    netlink_subscriber: Option<NamespaceEventSubscriber>,
}

impl UnifiedNamespaceWatcher {
    pub async fn new() -> Result<(Self, mpsc::Receiver<NamespaceEvent>)> {
        let (tx, rx) = mpsc::channel(100);
        
        // Start filesystem watcher (handles named namespaces)
        let (fs_watcher, mut fs_events) = NamespaceWatcher::new()?;
        
        // Try to start netlink subscriber (may fail on older kernels)
        let netlink_subscriber = NamespaceEventSubscriber::new().await.ok();
        
        // Merge event streams...
        
        Ok((Self { fs_watcher, netlink_subscriber }, rx))
    }
}
```

---

## Implementation Order

### Phase 1: Filesystem Watcher (Solution 4)

1. Add `notify` dependency (optional feature)
2. Implement `NamespaceWatcher` with parent directory fallback
3. Add tests
4. Document API

**Estimated effort**: 2-3 hours

### Phase 2: Netlink Events (Solution 5)

1. Add namespace netlink constants and types
2. Implement multicast group subscription
3. Implement `NsIdMessage` parsing
4. Implement `NamespaceEventSubscriber`
5. Add RTM_GETNSID query support
6. Add tests
7. Document API

**Estimated effort**: 4-6 hours

### Phase 3: Hybrid/Unified Watcher

1. Create unified API that uses both approaches
2. Handle event deduplication
3. Add comprehensive tests
4. Document trade-offs and configuration

**Estimated effort**: 2-3 hours

---

## Files to Create/Modify

### New Files

| File | Purpose |
|------|---------|
| `src/netlink/namespace_watcher.rs` | Filesystem-based watcher (Solution 4) |
| `src/netlink/namespace_events.rs` | Netlink event subscriber (Solution 5) |
| `src/netlink/messages/namespace.rs` | NsIdMessage parsing |
| `src/netlink/types/namespace.rs` | Namespace-related constants |

### Modified Files

| File | Changes |
|------|---------|
| `Cargo.toml` | Add `notify` optional dependency |
| `src/netlink/mod.rs` | Export new modules |
| `src/netlink/socket.rs` | Add `add_membership()` method |
| `src/netlink/connection.rs` | Add `get_nsid()` methods |
| `src/lib.rs` | Re-export namespace watcher types |

---

## Testing Checklist

### Filesystem Watcher Tests

- [ ] Watcher creation when `/var/run/netns/` exists
- [ ] Watcher creation when `/var/run/netns/` doesn't exist
- [ ] Detect namespace creation
- [ ] Detect namespace deletion
- [ ] Handle directory creation after watcher starts
- [ ] Handle directory deletion while watching
- [ ] Multiple rapid create/delete operations
- [ ] Permissions handling

### Netlink Event Tests

- [ ] Subscriber creation
- [ ] Multicast group subscription
- [ ] Parse RTM_NEWNSID message
- [ ] Parse RTM_DELNSID message
- [ ] RTM_GETNSID query
- [ ] Handle older kernels gracefully

### Integration Tests

- [ ] Create namespace with `ip netns add` - verify event
- [ ] Delete namespace with `ip netns del` - verify event
- [ ] Fresh boot scenario (no /var/run/netns)
- [ ] Stress test with many namespaces
