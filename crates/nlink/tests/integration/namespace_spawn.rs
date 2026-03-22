//! Namespace process spawning integration tests.
//!
//! Tests for spawning processes inside network namespaces.

use nlink::Result;
use nlink::netlink::link::DummyLink;
use nlink::netlink::namespace;
use nlink::netlink::namespace::NamespaceSpec;
use std::process::Command;

use crate::common::TestNamespace;

#[tokio::test]
async fn test_spawn_ip_link_show() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-ip")?;

    let mut cmd = Command::new("ip");
    cmd.arg("link");
    let output = namespace::spawn_output(ns.name(), cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Every namespace has a loopback interface
    assert!(stdout.contains("lo"), "should contain loopback interface");

    Ok(())
}

#[tokio::test]
async fn test_spawn_sees_namespace_interface() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-if")?;
    let conn = ns.connection()?;

    // Create a dummy interface in the namespace
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    // Spawn ip link show in the namespace and verify the interface is visible
    let mut cmd = Command::new("ip");
    cmd.arg("link");
    let output = namespace::spawn_output(ns.name(), cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("test0"), "should see test0 in namespace");

    Ok(())
}

#[tokio::test]
async fn test_spawn_background_process() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-bg")?;

    // Spawn a sleep process in the namespace
    let mut cmd = Command::new("sleep");
    cmd.arg("60");
    let mut child = namespace::spawn(ns.name(), cmd)?;

    // Verify it's running
    let try_wait = child.try_wait().map_err(nlink::Error::Io)?;
    assert!(try_wait.is_none(), "process should still be running");

    // Kill it
    child.kill().map_err(nlink::Error::Io)?;
    child.wait().map_err(nlink::Error::Io)?;

    Ok(())
}

#[tokio::test]
async fn test_spawn_captures_stdout() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-out")?;

    let mut cmd = Command::new("echo");
    cmd.arg("hello from namespace");
    let output = namespace::spawn_output(ns.name(), cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(stdout.trim(), "hello from namespace");

    Ok(())
}

#[tokio::test]
async fn test_spawn_nonexistent_namespace() -> Result<()> {
    require_root!();

    let result = namespace::spawn("definitely_does_not_exist_12345", Command::new("true"));
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_spawn_nonexistent_binary() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-nobin")?;

    let result = namespace::spawn(ns.name(), Command::new("nonexistent_binary_12345"));
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_spawn_parent_namespace_unaffected() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-parent")?;
    let conn = ns.connection()?;

    // Create an interface only in the namespace
    conn.add_link(DummyLink::new("nsonly0")).await?;

    // Spawn a process in the namespace
    let mut cmd = Command::new("ip");
    cmd.arg("link");
    let output = namespace::spawn_output(ns.name(), cmd)?;
    let ns_stdout = String::from_utf8_lossy(&output.stdout);
    assert!(ns_stdout.contains("nsonly0"));

    // Verify the parent namespace doesn't have this interface
    let parent_output = Command::new("ip")
        .arg("link")
        .output()
        .map_err(nlink::Error::Io)?;
    let parent_stdout = String::from_utf8_lossy(&parent_output.stdout);
    assert!(
        !parent_stdout.contains("nsonly0"),
        "parent namespace should not have nsonly0"
    );

    Ok(())
}

#[tokio::test]
async fn test_namespace_spec_spawn() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-spec")?;

    let spec = NamespaceSpec::Named(ns.name());
    let mut cmd = Command::new("echo");
    cmd.arg("via spec");
    let output = spec.spawn_output(cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(stdout.trim(), "via spec");

    Ok(())
}
