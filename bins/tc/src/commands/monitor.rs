//! tc monitor - watch for traffic control events.

use clap::{Args, ValueEnum};
use rip_netlink::attr::{AttrIter, get};
use rip_netlink::message::{MessageIter, NlMsgType};
use rip_netlink::rtnetlink_groups::*;
use rip_netlink::types::tc::{TcMsg, TcaAttr, tc_handle};
use rip_netlink::{Connection, Protocol, Result};
use rip_output::{OutputFormat, OutputOptions};
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

        // Subscribe to TC multicast group
        conn.subscribe(RTNLGRP_TC)?;

        let mut stdout = io::stdout().lock();

        if format == OutputFormat::Text {
            writeln!(stdout, "Monitoring TC events (Ctrl+C to stop)...")?;
        }

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

                if self.timestamp {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    write!(stdout, "[{}.{:03}] ", now.as_secs(), now.subsec_millis())?;
                }

                match format {
                    OutputFormat::Text => {
                        self.print_event_text(&mut stdout, header.nlmsg_type, payload, opts)?;
                    }
                    OutputFormat::Json => {
                        self.print_event_json(&mut stdout, header.nlmsg_type, payload)?;
                    }
                }
            }
        }
    }

    fn print_event_text(
        &self,
        out: &mut impl Write,
        msg_type: u16,
        payload: &[u8],
        opts: &OutputOptions,
    ) -> Result<()> {
        let tcmsg = TcMsg::from_bytes(payload)?;
        let attrs_data = &payload[TcMsg::SIZE..];

        let mut kind = String::new();
        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            if TcaAttr::from(attr_type) == TcaAttr::Kind {
                kind = get::string(attr_data).unwrap_or("").to_string();
                break;
            }
        }

        let dev = rip_lib::ifname::index_to_name(tcmsg.tcm_ifindex as u32)
            .unwrap_or_else(|_| format!("if{}", tcmsg.tcm_ifindex));

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

        if !kind.is_empty() {
            write!(out, "{} ", kind)?;
        }

        write!(out, "{} ", tc_handle::format(tcmsg.tcm_handle))?;
        write!(out, "dev {} ", dev)?;

        if tcmsg.tcm_parent == tc_handle::ROOT {
            write!(out, "root")?;
        } else if tcmsg.tcm_parent == tc_handle::INGRESS {
            write!(out, "ingress")?;
        } else if tcmsg.tcm_parent != 0 {
            write!(out, "parent {}", tc_handle::format(tcmsg.tcm_parent))?;
        }

        writeln!(out)?;

        if opts.details {
            // Show additional details from attributes
            for (attr_type, attr_data) in AttrIter::new(attrs_data) {
                match TcaAttr::from(attr_type) {
                    TcaAttr::Options => {
                        writeln!(out, "  options: {} bytes", attr_data.len())?;
                    }
                    TcaAttr::Stats2 => {
                        writeln!(out, "  stats: {} bytes", attr_data.len())?;
                    }
                    _ => {}
                }
            }
        }

        out.flush()?;
        Ok(())
    }

    fn print_event_json(&self, out: &mut impl Write, msg_type: u16, payload: &[u8]) -> Result<()> {
        let tcmsg = TcMsg::from_bytes(payload)?;
        let attrs_data = &payload[TcMsg::SIZE..];

        let mut kind = String::new();
        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            if TcaAttr::from(attr_type) == TcaAttr::Kind {
                kind = get::string(attr_data).unwrap_or("").to_string();
                break;
            }
        }

        let dev = rip_lib::ifname::index_to_name(tcmsg.tcm_ifindex as u32)
            .unwrap_or_else(|_| format!("if{}", tcmsg.tcm_ifindex));

        let (action, object) = match msg_type {
            NlMsgType::RTM_NEWQDISC => ("add", "qdisc"),
            NlMsgType::RTM_DELQDISC => ("del", "qdisc"),
            NlMsgType::RTM_NEWTCLASS => ("add", "class"),
            NlMsgType::RTM_DELTCLASS => ("del", "class"),
            NlMsgType::RTM_NEWTFILTER => ("add", "filter"),
            NlMsgType::RTM_DELTFILTER => ("del", "filter"),
            _ => ("unknown", "unknown"),
        };

        let parent = if tcmsg.tcm_parent == tc_handle::ROOT {
            "root".to_string()
        } else if tcmsg.tcm_parent == tc_handle::INGRESS {
            "ingress".to_string()
        } else {
            tc_handle::format(tcmsg.tcm_parent)
        };

        let event = serde_json::json!({
            "event": object,
            "action": action,
            "kind": kind,
            "handle": tc_handle::format(tcmsg.tcm_handle),
            "dev": dev,
            "parent": parent,
            "ifindex": tcmsg.tcm_ifindex,
        });

        writeln!(out, "{}", serde_json::to_string(&event)?)?;
        out.flush()?;
        Ok(())
    }
}
