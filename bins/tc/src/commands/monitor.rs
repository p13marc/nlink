//! tc monitor - watch for traffic control events.
//!
//! This module uses the EventStream API from nlink for high-level
//! event monitoring with Stream trait support.

use clap::{Args, ValueEnum};
use nlink::netlink::Result;
use nlink::netlink::events::{EventStream, NetworkEvent};
use nlink::netlink::types::tc::tc_handle;
use nlink::output::{
    MonitorConfig, OutputFormat, OutputOptions, TcEvent, print_event, print_monitor_start,
};
use tokio_stream::StreamExt;

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
        // Build monitor config
        let config = MonitorConfig::new()
            .with_timestamp(self.timestamp)
            .with_format(format)
            .with_opts(*opts);

        // Build EventStream for TC events
        let mut stream = EventStream::builder().tc(true).build()?;

        let mut stdout = std::io::stdout().lock();
        print_monitor_start(
            &mut stdout,
            &config,
            "Monitoring TC events (Ctrl+C to stop)...",
        )?;

        // Determine which event types to monitor
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

        // Use try_next() for idiomatic async iteration with ? operator
        while let Some(event) = stream.try_next().await? {
            if let Some(tc_event) =
                convert_event(event, monitor_qdisc, monitor_class, monitor_filter)
            {
                print_event(&mut stdout, &tc_event, &config)?;
            }
        }

        Ok(())
    }
}

/// Convert a NetworkEvent to a TcEvent for output formatting.
fn convert_event(
    event: NetworkEvent,
    monitor_qdisc: bool,
    monitor_class: bool,
    monitor_filter: bool,
) -> Option<TcEvent> {
    let (tc_msg, object, action, should_show) = match event {
        NetworkEvent::NewQdisc(tc) => (tc, "qdisc", "added", monitor_qdisc),
        NetworkEvent::DelQdisc(tc) => (tc, "qdisc", "deleted", monitor_qdisc),
        NetworkEvent::NewClass(tc) => (tc, "class", "added", monitor_class),
        NetworkEvent::DelClass(tc) => (tc, "class", "deleted", monitor_class),
        NetworkEvent::NewFilter(tc) => (tc, "filter", "added", monitor_filter),
        NetworkEvent::DelFilter(tc) => (tc, "filter", "deleted", monitor_filter),
        _ => return None,
    };

    if !should_show {
        return None;
    }

    let dev = nlink::util::ifname::index_to_name(tc_msg.ifindex())
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
