//! tc monitor - watch for traffic control events.

use clap::{Args, ValueEnum};
use rip_netlink::message::{MessageIter, NlMsgType};
use rip_netlink::messages::TcMessage;
use rip_netlink::parse::FromNetlink;
use rip_netlink::rtnetlink_groups::*;
use rip_netlink::types::tc::tc_handle;
use rip_netlink::{Connection, Protocol, Result};
use rip_output::{
    MonitorConfig, OutputFormat, OutputOptions, print_monitor_start, write_timestamp,
};
use std::io::{self, Write};

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

        let mut stdout = io::stdout().lock();

        print_monitor_start(
            &mut stdout,
            &config,
            "Monitoring TC events (Ctrl+C to stop)...",
        )?;

        // Event loop
        loop {
            let data = conn.recv_event().await?;

            for result in MessageIter::new(&data) {
                let (header, payload) = result?;

                // Skip error/done/noop messages
                if header.is_error() || header.is_done() || header.nlmsg_type == NlMsgType::NOOP {
                    continue;
                }

                // Filter by event type
                let event_type = match header.nlmsg_type {
                    NlMsgType::RTM_NEWQDISC | NlMsgType::RTM_DELQDISC => TcEventType::Qdisc,
                    NlMsgType::RTM_NEWTCLASS | NlMsgType::RTM_DELTCLASS => TcEventType::Class,
                    NlMsgType::RTM_NEWTFILTER | NlMsgType::RTM_DELTFILTER => TcEventType::Filter,
                    _ => continue,
                };

                let should_show = self
                    .objects
                    .iter()
                    .any(|o| matches!(o, TcEventType::All) || *o == event_type);

                if !should_show {
                    continue;
                }

                // Parse TC message using typed API
                let tc_msg = match TcMessage::from_bytes(payload) {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };

                write_timestamp(&mut stdout, &config)?;

                match format {
                    OutputFormat::Text => {
                        print_event_text(&mut stdout, header.nlmsg_type, &tc_msg, opts)?;
                    }
                    OutputFormat::Json => {
                        print_event_json(&mut stdout, header.nlmsg_type, &tc_msg)?;
                    }
                }
            }
        }
    }
}

/// Print TC event in text format.
fn print_event_text(
    out: &mut impl Write,
    msg_type: u16,
    tc_msg: &TcMessage,
    opts: &OutputOptions,
) -> Result<()> {
    let dev = rip_lib::ifname::index_to_name(tc_msg.ifindex() as u32)
        .unwrap_or_else(|_| format!("if{}", tc_msg.ifindex()));

    let (action, object) = match msg_type {
        NlMsgType::RTM_NEWQDISC => ("added", "qdisc"),
        NlMsgType::RTM_DELQDISC => ("deleted", "qdisc"),
        NlMsgType::RTM_NEWTCLASS => ("added", "class"),
        NlMsgType::RTM_DELTCLASS => ("deleted", "class"),
        NlMsgType::RTM_NEWTFILTER => ("added", "filter"),
        NlMsgType::RTM_DELTFILTER => ("deleted", "filter"),
        _ => ("unknown", "unknown"),
    };

    write!(out, "{} {} ", action, object)?;

    if let Some(kind) = tc_msg.kind()
        && !kind.is_empty()
    {
        write!(out, "{} ", kind)?;
    }

    write!(out, "{} ", tc_handle::format(tc_msg.handle()))?;
    write!(out, "dev {} ", dev)?;

    if tc_msg.parent() == tc_handle::ROOT {
        write!(out, "root")?;
    } else if tc_msg.parent() == tc_handle::INGRESS {
        write!(out, "ingress")?;
    } else if tc_msg.parent() != 0 {
        write!(out, "parent {}", tc_handle::format(tc_msg.parent()))?;
    }

    writeln!(out)?;

    if opts.details {
        // Show additional details
        if tc_msg.options.is_some() {
            writeln!(
                out,
                "  options: {} bytes",
                tc_msg.options.as_ref().map_or(0, |o| o.len())
            )?;
        }
        if tc_msg.stats_basic.is_some() || tc_msg.stats_queue.is_some() {
            writeln!(out, "  stats: present")?;
        }
    }

    out.flush()?;
    Ok(())
}

/// Print TC event in JSON format.
fn print_event_json(out: &mut impl Write, msg_type: u16, tc_msg: &TcMessage) -> Result<()> {
    let dev = rip_lib::ifname::index_to_name(tc_msg.ifindex() as u32)
        .unwrap_or_else(|_| format!("if{}", tc_msg.ifindex()));

    let (action, object) = match msg_type {
        NlMsgType::RTM_NEWQDISC => ("add", "qdisc"),
        NlMsgType::RTM_DELQDISC => ("del", "qdisc"),
        NlMsgType::RTM_NEWTCLASS => ("add", "class"),
        NlMsgType::RTM_DELTCLASS => ("del", "class"),
        NlMsgType::RTM_NEWTFILTER => ("add", "filter"),
        NlMsgType::RTM_DELTFILTER => ("del", "filter"),
        _ => ("unknown", "unknown"),
    };

    let parent = if tc_msg.parent() == tc_handle::ROOT {
        "root".to_string()
    } else if tc_msg.parent() == tc_handle::INGRESS {
        "ingress".to_string()
    } else {
        tc_handle::format(tc_msg.parent())
    };

    let event = serde_json::json!({
        "event": object,
        "action": action,
        "kind": tc_msg.kind().unwrap_or(""),
        "handle": tc_handle::format(tc_msg.handle()),
        "dev": dev,
        "parent": parent,
        "ifindex": tc_msg.ifindex(),
    });

    writeln!(out, "{}", serde_json::to_string(&event)?)?;
    out.flush()?;
    Ok(())
}
