//! Watch command - monitor network issues in real-time.

use clap::Args;
use nlink::netlink::diagnostics::{Diagnostics, Severity};
use nlink::netlink::{Connection, Result, Route};
use tokio_stream::StreamExt;

#[derive(Args)]
pub struct WatchArgs {
    /// Only show issues of this severity or higher
    #[arg(long, value_parser = parse_severity)]
    pub min_severity: Option<Severity>,
}

fn parse_severity(s: &str) -> std::result::Result<Severity, String> {
    match s.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "warning" | "warn" => Ok(Severity::Warning),
        "error" => Ok(Severity::Error),
        "critical" => Ok(Severity::Critical),
        _ => Err(format!("Unknown severity: {}", s)),
    }
}

pub async fn run(args: WatchArgs, json: bool) -> Result<()> {
    let conn = Connection::<Route>::new()?;
    let diag = Diagnostics::new(conn);

    let min_severity = args.min_severity.unwrap_or(Severity::Info);

    eprintln!(
        "Watching for network issues (min severity: {:?})...",
        min_severity
    );
    eprintln!("Press Ctrl+C to stop.");
    eprintln!();

    let mut issues = diag.watch().await?;

    while let Some(result) = issues.next().await {
        let issue = result?;

        if issue.severity < min_severity {
            continue;
        }

        if json {
            let output = serde_json::json!({
                "severity": format!("{:?}", issue.severity),
                "category": format!("{:?}", issue.category),
                "message": issue.message,
                "details": issue.details,
                "interface": issue.interface,
            });
            println!("{}", serde_json::to_string(&output).unwrap());
        } else {
            let icon = match issue.severity {
                Severity::Info => "[INFO]",
                Severity::Warning => "[WARN]",
                Severity::Error => "[ERROR]",
                Severity::Critical => "[CRIT]",
            };

            let iface = issue
                .interface
                .as_ref()
                .map(|s| format!("[{}] ", s))
                .unwrap_or_default();

            println!("{} {}{}", icon, iface, issue.message);
            if let Some(ref details) = issue.details {
                println!("      {}", details);
            }
        }
    }

    Ok(())
}
