//! tc monitor - watch for traffic control events.
//!
//! This module uses the strongly-typed message API from rip-netlink
//! and the generic monitor infrastructure from rip-output.

use clap::{Args, ValueEnum};
use rip::netlink::message::NlMsgType;
use rip::netlink::messages::TcMessage;
use rip::netlink::parse::FromNetlink;
use rip::netlink::rtnetlink_groups::*;
use rip::netlink::types::tc::tc_handle;
use rip::netlink::{Connection, Protocol, Result};
use rip::output::{
    MonitorConfig, OutputFormat, OutputOptions, TcEvent, print_monitor_start, run_monitor_loop,
};

/// Event types that can be monitored.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum TcEventType {
    /// Qdisc changes.
    Qdisc,
    /// Class changes.
    Class,
    /// Filter changes.
    Filter,
    /// All TC event types.
    All,
}

#[derive(Args)]
pub struct MonitorCmd {
    /// Event types to monitor.
    #[arg(default_value = "all")]
    objects: Vec<TcEventType>,

    /// Label output lines with event timestamps.
    #[arg(short = 't', long)]
    timestamp: bool,
}

impl MonitorCmd {
    pub async fn run(&self, format: OutputFormat, opts: &OutputOptions) -> Result<()> {
        let mut conn = Connection::new(Protocol::Route)?;

        // Build monitor config
        let config = MonitorConfig::new()
            .with_timestamp(self.timestamp)
            .with_format(format)
            .with_opts(*opts);

        // Subscribe to TC multicast group
        conn.subscribe(RTNLGRP_TC)?;

        let mut stdout = std::io::stdout().lock();
        print_monitor_start(
            &mut stdout,
            &config,
            "Monitoring TC events (Ctrl+C to stop)...",
        )?;
        drop(stdout);

        // Capture which event types to monitor
        let monitor_qdisc = self
            .objects
            .iter()
            .any(|o| matches!(o, TcEventType::Qdisc | TcEventType::All));
        let monitor_class = self
            .objects
            .iter()
            .any(|o| matches!(o, TcEventType::Class | TcEventType::All));
        let monitor_filter = self
            .objects
            .iter()
            .any(|o| matches!(o, TcEventType::Filter | TcEventType::All));

        // Run the monitor loop with event handler
        run_monitor_loop(&conn, &config, |msg_type, payload| {
            parse_tc_event(
                msg_type,
                payload,
                monitor_qdisc,
                monitor_class,
                monitor_filter,
            )
        })
        .await
    }
}

/// Parse a netlink message into a TC event.
fn parse_tc_event(
    msg_type: u16,
    payload: &[u8],
    monitor_qdisc: bool,
    monitor_class: bool,
    monitor_filter: bool,
) -> Option<TcEvent> {
    // Determine object type and action
    let (object, action, should_show) = match msg_type {
        NlMsgType::RTM_NEWQDISC => ("qdisc", "added", monitor_qdisc),
        NlMsgType::RTM_DELQDISC => ("qdisc", "deleted", monitor_qdisc),
        NlMsgType::RTM_NEWTCLASS => ("class", "added", monitor_class),
        NlMsgType::RTM_DELTCLASS => ("class", "deleted", monitor_class),
        NlMsgType::RTM_NEWTFILTER => ("filter", "added", monitor_filter),
        NlMsgType::RTM_DELTFILTER => ("filter", "deleted", monitor_filter),
        _ => return None,
    };

    if !should_show {
        return None;
    }

    // Parse TC message
    let tc_msg = TcMessage::from_bytes(payload).ok()?;

    let dev = rip::util::ifname::index_to_name(tc_msg.ifindex() as u32)
        .unwrap_or_else(|_| format!("if{}", tc_msg.ifindex()));

    let parent = if tc_msg.parent() == tc_handle::ROOT {
        "root".to_string()
    } else if tc_msg.parent() == tc_handle::INGRESS {
        "ingress".to_string()
    } else {
        tc_handle::format(tc_msg.parent())
    };

    Some(TcEvent {
        object,
        action,
        kind: tc_msg.kind().unwrap_or("").to_string(),
        handle: tc_handle::format(tc_msg.handle()),
        parent,
        dev,
        ifindex: tc_msg.ifindex(),
    })
}
