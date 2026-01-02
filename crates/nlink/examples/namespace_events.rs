//! Monitor namespace ID events via netlink.
//!
//! This example demonstrates how to receive RTM_NEWNSID/RTM_DELNSID
//! kernel events when namespace IDs are assigned or released.
//!
//! Run with: cargo run -p nlink --example namespace_events
//!
//! Then in another terminal:
//!   sudo ip netns add test1
//!   sudo ip netns del test1

use nlink::netlink::{NamespaceEventSubscriber, NamespaceNetlinkEvent};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    println!("Monitoring namespace ID events (Ctrl+C to stop)...\n");
    println!("Note: Events are triggered when namespace IDs are assigned,");
    println!("which happens when the kernel needs to track a namespace.\n");
    println!("{}", "-".repeat(50));

    let mut subscriber = NamespaceEventSubscriber::new().await?;

    while let Some(event) = subscriber.recv().await? {
        match event {
            NamespaceNetlinkEvent::NewNsId { nsid, pid, fd } => {
                println!("[+] New namespace ID: {}", nsid);
                if let Some(p) = pid {
                    println!("    origin: PID {}", p);
                }
                if let Some(f) = fd {
                    println!("    origin: fd {}", f);
                }
            }
            NamespaceNetlinkEvent::DelNsId { nsid } => {
                println!("[-] Deleted namespace ID: {}", nsid);
            }
        }
    }

    Ok(())
}
