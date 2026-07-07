//! `NamespaceWatcher` lifecycle integration tests (#183).
//!
//! Drives a real create → event → delete → event round-trip through the
//! inotify-backed watcher. The unit test in `namespace_watcher.rs` covers
//! the unprivileged half of #183 (recv parks instead of erroring); this
//! covers the privileged half (events actually arrive).

use nlink::{
    Result,
    netlink::{
        namespace,
        namespace_watcher::{NamespaceEvent, NamespaceWatcher},
    },
};

/// Drain events until `pred` matches or the deadline passes. Unrelated
/// namespace churn from concurrent tests is skipped, not failed on.
async fn wait_for_event(
    watcher: &mut NamespaceWatcher,
    mut pred: impl FnMut(&NamespaceEvent) -> bool,
) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, watcher.recv()).await {
            Err(_elapsed) => return false,
            Ok(Ok(Some(event))) if pred(&event) => return true,
            Ok(Ok(Some(_unrelated))) => continue,
            Ok(Ok(None)) | Ok(Err(_)) => return false,
        }
    }
}

#[tokio::test]
async fn test_watcher_observes_create_and_delete() -> Result<()> {
    require_root!();

    let name = format!("nlink-watch-{}", std::process::id());
    let mut watcher = NamespaceWatcher::new().await?;

    namespace::create(&name)?;
    let saw_created = wait_for_event(&mut watcher, |e| {
        matches!(e, NamespaceEvent::Created { name: n } if *n == name)
    })
    .await;

    // Delete before asserting so a failed assertion can't leak the netns.
    namespace::delete(&name)?;
    assert!(saw_created, "watcher should observe Created {{ {name} }}");

    let saw_deleted = wait_for_event(&mut watcher, |e| {
        matches!(e, NamespaceEvent::Deleted { name: n } if *n == name)
    })
    .await;
    assert!(saw_deleted, "watcher should observe Deleted {{ {name} }}");

    Ok(())
}
