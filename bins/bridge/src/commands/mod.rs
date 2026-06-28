//! bridge subcommands

pub mod fdb;
pub mod link;
pub mod mdb;
pub mod monitor;
pub mod vlan;

/// Serialize a value to a JSON string, mapping a (practically
/// impossible) serialization failure to a clean `Error` instead of
/// panicking via `.expect()`. Shared by the JSON show paths.
pub(crate) fn to_json_string<T: serde::Serialize>(
    value: &T,
    pretty: bool,
) -> nlink::netlink::Result<String> {
    let result = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    };
    result.map_err(|e| {
        nlink::netlink::Error::InvalidMessage(format!("JSON serialization failed: {e}"))
    })
}
