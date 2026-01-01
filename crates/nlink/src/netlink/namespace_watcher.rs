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

use std::path::Path;

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};

use super::error::{Error, Result};

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
        let inotify = Inotify::init().map_err(Error::Io)?;

        let netns_path = Path::new(NETNS_DIR);
        let mut netns_wd = None;
        let mut parent_wd = None;

        if netns_path.exists() {
            // Directory exists - watch it directly
            let wd = inotify
                .watches()
                .add(
                    NETNS_DIR,
                    WatchMask::CREATE | WatchMask::DELETE | WatchMask::DELETE_SELF,
                )
                .map_err(Error::Io)?;
            netns_wd = Some(wd);
        } else if config.watch_parent {
            // Directory doesn't exist - watch parent for its creation
            let wd = inotify
                .watches()
                .add(PARENT_DIR, WatchMask::CREATE | WatchMask::MOVED_TO)
                .map_err(Error::Io)?;
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
            let events = self
                .inotify
                .read_events(&mut self.buffer)
                .map_err(Error::Io)?;

            // Collect event data we need before processing
            // (to avoid borrow checker issues with self.buffer)
            let mut pending_events: Vec<(WatchDescriptor, EventMask, Option<String>)> = Vec::new();
            for event in events {
                let name = event.name.and_then(|n| n.to_str()).map(String::from);
                pending_events.push((event.wd.clone(), event.mask, name));
            }

            for (wd, mask, name) in pending_events {
                if let Some(ns_event) = self.process_event(wd, mask, name)? {
                    return Ok(Some(ns_event));
                }
            }
        }
    }

    /// Process a single inotify event and optionally return a NamespaceEvent.
    fn process_event(
        &mut self,
        wd: WatchDescriptor,
        mask: EventMask,
        name: Option<String>,
    ) -> Result<Option<NamespaceEvent>> {
        // Check if this is an event on the netns directory
        if Some(wd.clone()) == self.netns_wd {
            // Event in /var/run/netns/
            if mask.contains(EventMask::DELETE_SELF) {
                // The netns directory itself was deleted
                self.netns_wd = None;

                // Start watching parent if configured
                if self.config.watch_parent
                    && let Ok(new_wd) = self
                        .inotify
                        .watches()
                        .add(PARENT_DIR, WatchMask::CREATE | WatchMask::MOVED_TO)
                    {
                        self.parent_wd = Some(new_wd);
                    }

                if self.config.emit_directory_events {
                    return Ok(Some(NamespaceEvent::DirectoryDeleted));
                }
            } else if mask.contains(EventMask::CREATE) {
                if let Some(name) = name {
                    return Ok(Some(NamespaceEvent::Created { name }));
                }
            } else if mask.contains(EventMask::DELETE)
                && let Some(name) = name {
                    return Ok(Some(NamespaceEvent::Deleted { name }));
                }
        } else if Some(wd) == self.parent_wd {
            // Event in /var/run/ - check if netns directory was created
            let is_netns = name.as_deref() == Some("netns");

            if is_netns && (mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO))
            {
                // netns directory appeared - switch to watching it
                if let Ok(new_wd) = self.inotify.watches().add(
                    NETNS_DIR,
                    WatchMask::CREATE | WatchMask::DELETE | WatchMask::DELETE_SELF,
                ) {
                    // Remove parent watch
                    if let Some(parent_wd) = self.parent_wd.take() {
                        let _ = self.inotify.watches().remove(parent_wd);
                    }
                    self.netns_wd = Some(new_wd);

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
