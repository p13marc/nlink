//! Integration tests for rip-netlink.
//!
//! These tests require network namespace isolation to run safely.
//! Run with: `sudo unshare -n cargo test -p rip-netlink --test integration --features integration`
//!
//! The tests are gated behind the `integration` feature to avoid running
//! them in normal CI without proper setup.

#![cfg(feature = "integration")]

use rip_netlink::{Connection, Protocol};
use std::time::Duration;

/// Helper to create a connection for tests.
fn connect() -> Connection {
    Connection::new(Protocol::Route).expect("failed to create connection")
}

mod link_tests {
    use super::*;
    use rip_netlink::message::NlMsgType;
    use rip_netlink::messages::LinkMessage;

    #[tokio::test]
    async fn test_get_loopback() {
        let conn = connect();
        let links: Vec<LinkMessage> = conn.dump_typed(NlMsgType::RTM_GETLINK).await.unwrap();

        // Loopback should always exist
        let lo = links.iter().find(|l| l.name.as_deref() == Some("lo"));
        assert!(lo.is_some(), "loopback interface not found");

        let lo = lo.unwrap();
        assert_eq!(lo.ifindex(), 1);
        assert!(lo.is_loopback());
    }

    #[tokio::test]
    async fn test_get_links_convenience() {
        let conn = connect();
        let links = conn.get_links().await.unwrap();

        // Should have at least loopback
        assert!(!links.is_empty());
        assert!(links.iter().any(|l| l.name.as_deref() == Some("lo")));
    }
}

mod address_tests {
    use super::*;
    use rip_netlink::message::NlMsgType;
    use rip_netlink::messages::AddressMessage;

    #[tokio::test]
    async fn test_get_loopback_addresses() {
        let conn = connect();
        let addrs: Vec<AddressMessage> = conn.dump_typed(NlMsgType::RTM_GETADDR).await.unwrap();

        // Loopback should have 127.0.0.1 and ::1
        let lo_addrs: Vec<_> = addrs.iter().filter(|a| a.ifindex() == 1).collect();

        // At least one address on lo
        assert!(
            !lo_addrs.is_empty(),
            "no addresses on loopback (may need to run in network namespace)"
        );
    }

    #[tokio::test]
    async fn test_get_addresses_convenience() {
        let conn = connect();
        let addrs = conn.get_addresses().await.unwrap();

        // Should have at least some addresses
        // Note: in a fresh network namespace, only lo addresses exist
        assert!(addrs.iter().any(|a| a.ifindex() == 1));
    }
}

mod route_tests {
    use super::*;

    #[tokio::test]
    async fn test_get_routes() {
        let conn = connect();
        let routes = conn.get_routes().await.unwrap();

        // In a network namespace, we should have at least local routes
        // The local table always has entries for loopback
        let _ = routes; // May be empty in minimal namespace, just verify it works
    }
}

mod neighbor_tests {
    use super::*;

    #[tokio::test]
    async fn test_get_neighbors() {
        let conn = connect();
        let neighbors = conn.get_neighbors().await.unwrap();

        // Neighbor table may be empty in a fresh namespace
        // Just verify the query works
        let _ = neighbors;
    }
}

mod tc_tests {
    use super::*;
    use rip_netlink::message::NlMsgType;
    use rip_netlink::messages::TcMessage;

    #[tokio::test]
    async fn test_get_qdiscs() {
        let conn = connect();
        let qdiscs: Vec<TcMessage> = conn.dump_typed(NlMsgType::RTM_GETQDISC).await.unwrap();

        // Loopback should have a default qdisc
        let lo_qdiscs: Vec<_> = qdiscs.iter().filter(|q| q.ifindex() == 1).collect();
        assert!(
            !lo_qdiscs.is_empty(),
            "no qdiscs on loopback (kernel should have default)"
        );
    }

    #[tokio::test]
    async fn test_get_qdiscs_convenience() {
        let conn = connect();
        let qdiscs = conn.get_qdiscs().await.unwrap();

        // Should have at least one qdisc
        assert!(!qdiscs.is_empty());
    }
}

mod tc_modification_tests {
    use super::*;
    use rip_netlink::tc::NetemConfig;

    /// Test adding and removing a netem qdisc.
    /// This test requires a dummy interface to be created first.
    #[tokio::test]
    async fn test_add_del_netem_qdisc() {
        let conn = connect();

        // First, create a dummy interface for testing
        // We need to use the low-level API for this
        use rip_netlink::connection::ack_request;
        use rip_netlink::message::NlMsgType;
        use rip_netlink::types::link::{IfInfoMsg, IflaAttr, iff};

        let dev_name = "test-netem0";

        // Create dummy interface
        let ifinfo = IfInfoMsg::new();
        let mut builder = ack_request(NlMsgType::RTM_NEWLINK);
        builder.append(&ifinfo);
        builder.append_attr_str(IflaAttr::Ifname as u16, dev_name);

        // Add IFLA_LINKINFO with kind="dummy"
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(1, "dummy"); // IFLA_INFO_KIND = 1
        builder.nest_end(linkinfo);

        let create_result = conn.request_ack(builder).await;
        if create_result.is_err() {
            // May already exist or lack permissions
            eprintln!(
                "Failed to create dummy interface (may need root): {:?}",
                create_result
            );
            return;
        }

        // Bring interface up
        let ifindex = rip_lib::ifname::name_to_index(dev_name).unwrap() as i32;
        let mut ifinfo = IfInfoMsg::new().with_index(ifindex);
        ifinfo.ifi_flags = iff::UP;
        ifinfo.ifi_change = iff::UP;
        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        conn.request_ack(builder).await.unwrap();

        // Add netem qdisc
        let netem = NetemConfig::new()
            .delay(Duration::from_millis(50))
            .jitter(Duration::from_millis(10))
            .loss(0.5)
            .build();

        let add_result = conn.add_qdisc(dev_name, netem).await;
        assert!(add_result.is_ok(), "failed to add netem: {:?}", add_result);

        // Verify qdisc exists
        let qdiscs = conn.get_qdiscs().await.unwrap();
        let netem_qdisc = qdiscs
            .iter()
            .find(|q| q.ifindex() == ifindex && q.kind() == Some("netem"));
        assert!(netem_qdisc.is_some(), "netem qdisc not found after add");

        // Delete qdisc
        let del_result = conn.del_qdisc(dev_name, "root").await;
        assert!(
            del_result.is_ok(),
            "failed to delete netem: {:?}",
            del_result
        );

        // Verify qdisc is gone (or replaced by default)
        let qdiscs = conn.get_qdiscs().await.unwrap();
        let netem_qdisc = qdiscs
            .iter()
            .find(|q| q.ifindex() == ifindex && q.kind() == Some("netem"));
        assert!(netem_qdisc.is_none(), "netem qdisc still exists after del");

        // Clean up: delete the dummy interface
        let ifinfo = IfInfoMsg::new().with_index(ifindex);
        let mut builder = ack_request(NlMsgType::RTM_DELLINK);
        builder.append(&ifinfo);
        let _ = conn.request_ack(builder).await;
    }

    /// Test replacing a qdisc.
    #[tokio::test]
    async fn test_replace_qdisc() {
        let conn = connect();

        use rip_netlink::connection::ack_request;
        use rip_netlink::message::NlMsgType;
        use rip_netlink::types::link::{IfInfoMsg, IflaAttr, iff};

        let dev_name = "test-repl0";

        // Create dummy interface
        let ifinfo = IfInfoMsg::new();
        let mut builder = ack_request(NlMsgType::RTM_NEWLINK);
        builder.append(&ifinfo);
        builder.append_attr_str(IflaAttr::Ifname as u16, dev_name);
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(1, "dummy");
        builder.nest_end(linkinfo);

        if conn.request_ack(builder).await.is_err() {
            return; // Skip if can't create interface
        }

        // Bring interface up
        let ifindex = rip_lib::ifname::name_to_index(dev_name).unwrap() as i32;
        let mut ifinfo = IfInfoMsg::new().with_index(ifindex);
        ifinfo.ifi_flags = iff::UP;
        ifinfo.ifi_change = iff::UP;
        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        conn.request_ack(builder).await.unwrap();

        // Add initial netem
        let netem1 = NetemConfig::new().delay(Duration::from_millis(100)).build();
        conn.add_qdisc(dev_name, netem1).await.unwrap();

        // Replace with different config
        let netem2 = NetemConfig::new()
            .delay(Duration::from_millis(50))
            .loss(1.0)
            .build();
        let replace_result = conn.replace_qdisc(dev_name, netem2).await;
        assert!(
            replace_result.is_ok(),
            "failed to replace: {:?}",
            replace_result
        );

        // Clean up
        let ifinfo = IfInfoMsg::new().with_index(ifindex);
        let mut builder = ack_request(NlMsgType::RTM_DELLINK);
        builder.append(&ifinfo);
        let _ = conn.request_ack(builder).await;
    }
}
