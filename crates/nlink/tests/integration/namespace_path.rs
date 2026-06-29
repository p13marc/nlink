//! Path-based namespace lifecycle integration tests.
//!
//! Covers `namespace::create_path` / `delete_path` — persisting a netns at an
//! arbitrary, application-owned bind-mount path instead of the `ip netns`
//! convention `/var/run/netns/<name>`.

use std::path::PathBuf;

use nlink::{Connection, Result, Route, netlink::namespace};

/// A unique scratch directory under the system temp dir, removed on drop.
/// Deliberately *outside* `/var/run/netns` to exercise the
/// application-owned-directory path that distinguishes `create_path`.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("nlink-ns-path-{tag}-{}", std::process::id()));
        Self(dir)
    }

    fn join(&self, leaf: &str) -> PathBuf {
        self.0.join(leaf)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn test_create_path_round_trip() -> Result<()> {
    require_root!();

    let scratch = ScratchDir::new("rt");
    // Nested leaf so create_path must materialize the parent directory.
    let ns_path = scratch.join("nested/myns");

    namespace::create_path(&ns_path)?;

    assert!(ns_path.exists(), "marker file should exist after create_path");
    assert!(
        ns_path.parent().unwrap().exists(),
        "parent directory should have been created"
    );

    // A path-created netns must be openable via the path-based connection
    // helper — the loopback interface is always present in a fresh netns.
    let conn: Connection<Route> = namespace::connection_for_path(&ns_path)?;
    let links = conn.get_links().await?;
    assert!(
        links.iter().any(|l| l.name() == Some("lo")),
        "fresh netns should contain a loopback interface"
    );
    drop(conn);

    namespace::delete_path(&ns_path)?;
    assert!(
        !ns_path.exists(),
        "marker file should be gone after delete_path"
    );

    Ok(())
}

#[tokio::test]
async fn test_is_namespace_path_tracks_lifecycle() -> Result<()> {
    require_root!();

    let scratch = ScratchDir::new("isns");
    let ns_path = scratch.join("myns");

    assert!(!namespace::is_namespace_path(&ns_path), "absent → false");

    namespace::create_path(&ns_path)?;
    assert!(
        namespace::is_namespace_path(&ns_path),
        "live bind-mount → true"
    );

    namespace::delete_path(&ns_path)?;
    assert!(!namespace::is_namespace_path(&ns_path), "deleted → false");

    Ok(())
}

// Root-free cases (already-exists rejection, missing-path not-found,
// stale-marker → false) live as unit tests in `namespace.rs`; this file
// covers only the privileged round-trips above.
