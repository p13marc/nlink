//! Operation timeouts for netlink requests.
//!
//! Demonstrates setting timeouts on connections to prevent
//! indefinite blocking on unresponsive operations.
//!
//! Run with: cargo run -p nlink --example route_timeout

use nlink::netlink::{Connection, Route};
use std::time::Duration;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    // Default: no timeout (waits indefinitely)
    let conn = Connection::<Route>::new()?;
    assert_eq!(conn.get_timeout(), None);
    println!("Default timeout: none");

    // Set a 5-second timeout
    let conn = conn.timeout(Duration::from_secs(5));
    println!("Timeout set to: {:?}", conn.get_timeout().unwrap());

    // Operations respect the timeout
    let links = conn.get_links().await?;
    println!("Found {} interfaces (within timeout)", links.len());

    // Handle timeout errors
    let fast_conn = Connection::<Route>::new()?.timeout(Duration::from_nanos(1));
    match fast_conn.get_links().await {
        Ok(links) => println!("Got {} links (fast system!)", links.len()),
        Err(e) if e.is_timeout() => println!("Operation timed out (expected with 1ns timeout)"),
        Err(e) => return Err(e),
    }

    // Clear timeout
    let conn = conn.no_timeout();
    assert_eq!(conn.get_timeout(), None);
    println!("Timeout cleared.");

    Ok(())
}
