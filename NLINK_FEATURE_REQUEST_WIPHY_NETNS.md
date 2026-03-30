# nlink Feature Request: SET_WIPHY_NETNS for Wi-Fi PHY Namespace Movement

**Date:** 2026-03-30
**Requested by:** nlink-lab (Plan 112: Wi-Fi Emulation)
**Priority:** Medium (blocks nlink-lab Wi-Fi support without `iw` dependency)

---

## Summary

Add `set_wiphy_netns()` to `Connection<Nl80211>` to move a wireless PHY device
to a different network namespace. This is the nl80211 equivalent of
`iw phy <name> set netns name <ns>` and is the last missing piece for
fully programmatic Wi-Fi lab topology deployment.

## Motivation

nlink-lab's Wi-Fi emulation plan (Plan 112) uses `mac80211_hwsim` to create
virtual Wi-Fi radios and move them into network namespaces. Currently nlink's
nl80211 module supports **querying** PHYs (`get_phys()`, `get_phy()`) and
interfaces, but not **moving** PHYs between namespaces.

Without this, nlink-lab must shell out to `iw`:

```bash
iw phy phy0 set netns name my-namespace
```

This is the only `iw` dependency remaining — all other Wi-Fi operations (PHY
enumeration, interface listing, association verification, scan, station info)
already use nlink's nl80211 API.

## Existing nl80211 Support in nlink 0.12.0

nlink already has comprehensive nl80211 support:

| Capability | Method | Status |
|---|---|---|
| List PHYs | `get_phys()`, `get_phy(idx)` | Implemented |
| List interfaces | `get_interfaces()` | Implemented |
| Station info | `get_stations()`, `get_station()` | Implemented |
| Scan | `trigger_scan()`, `get_scan_results()` | Implemented |
| Connect/disconnect | `connect()`, `disconnect()` | Implemented |
| Power save | `set_power_save()`, `get_power_save()` | Implemented |
| Event subscription | Scan, MLME, regulatory groups | Implemented |
| **Move PHY to namespace** | — | **Missing** |

## Proposed API

### By namespace file descriptor

```rust
impl Connection<Nl80211> {
    /// Move a wireless PHY to a different network namespace.
    ///
    /// The PHY is identified by its wiphy index (from `get_phys()`).
    /// The target namespace is specified by file descriptor (from
    /// `namespace::open()` or `NamespaceFd`).
    ///
    /// After the move, all interfaces on this PHY appear inside the
    /// target namespace. The PHY can only be in one namespace at a time.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::namespace;
    ///
    /// let nl = Connection::<Nl80211>::new().await?;
    /// let phys = nl.get_phys().await?;
    /// let ns_fd = namespace::open("my-namespace")?;
    ///
    /// // Move phy0 to the namespace
    /// nl.set_wiphy_netns(phys[0].index, ns_fd.as_raw_fd()).await?;
    /// ```
    pub async fn set_wiphy_netns(&self, wiphy: u32, netns_fd: i32) -> Result<()>
}
```

### By namespace PID (convenience)

```rust
impl Connection<Nl80211> {
    /// Move a wireless PHY to the namespace of a given process.
    pub async fn set_wiphy_netns_pid(&self, wiphy: u32, pid: u32) -> Result<()>
}
```

## Implementation Details

### nl80211 Command

The kernel command is `NL80211_CMD_SET_WIPHY` with the `NL80211_ATTR_NETNS_FD`
attribute. This is the same command used for other wiphy settings, with the
namespace FD indicating a namespace move.

### Netlink Message Structure

```
Generic Netlink Header:
  cmd: NL80211_CMD_SET_WIPHY (2)
  version: 0

Attributes:
  NL80211_ATTR_WIPHY (1): u32 — wiphy index
  NL80211_ATTR_NETNS_FD (69): u32 — file descriptor of target namespace
```

For PID-based move:
```
  NL80211_ATTR_PID (82): u32 — target process PID (uses /proc/PID/ns/net)
```

### Reference: iproute2 Implementation

From `iw/phy.c` (`handle_netns`):

```c
static int handle_netns(struct nl80211_state *state,
                        struct nl_msg *msg, int argc, char **argv, ...)
{
    // ...
    if (strcmp(argv[0], "name") == 0) {
        netns_fd = netns_get_fd(argv[1]);
        NLA_PUT_U32(msg, NL80211_ATTR_NETNS_FD, netns_fd);
    } else if (strcmp(argv[0], "pid") == 0) {
        NLA_PUT_U32(msg, NL80211_ATTR_PID, pid);
    }
    // ...
}
```

### Implementation in nlink

```rust
// In nlink/src/netlink/genl/nl80211/connection.rs

pub async fn set_wiphy_netns(&self, wiphy: u32, netns_fd: i32) -> Result<()> {
    let family_id = self.family_id().await?;

    let mut builder = MessageBuilder::new();
    builder.set_cmd(Nl80211Cmd::SetWiphy as u8);

    // NL80211_ATTR_WIPHY = 1
    builder.append_attr_u32(1, wiphy);
    // NL80211_ATTR_NETNS_FD = 69
    builder.append_attr_u32(69, netns_fd as u32);

    self.send_ack(family_id, &builder).await
        .map_err(|e| e.with_context("set_wiphy_netns"))
}

pub async fn set_wiphy_netns_pid(&self, wiphy: u32, pid: u32) -> Result<()> {
    let family_id = self.family_id().await?;

    let mut builder = MessageBuilder::new();
    builder.set_cmd(Nl80211Cmd::SetWiphy as u8);

    // NL80211_ATTR_WIPHY = 1
    builder.append_attr_u32(1, wiphy);
    // NL80211_ATTR_PID = 82
    builder.append_attr_u32(82, pid);

    self.send_ack(family_id, &builder).await
        .map_err(|e| e.with_context("set_wiphy_netns_pid"))
}
```

### Constants

These constants likely already exist in nlink's nl80211 module (`mod.rs`):

```rust
// NL80211_CMD_SET_WIPHY = 2 (already defined as part of nl80211 commands)
// NL80211_ATTR_WIPHY = 1
// NL80211_ATTR_NETNS_FD = 69
// NL80211_ATTR_PID = 82
```

If `NL80211_ATTR_NETNS_FD` (69) and `NL80211_ATTR_PID` (82) are not yet
defined, they need to be added to the attribute enum.

## Testing

| Test | Description |
|------|-------------|
| `test_set_wiphy_netns` | Create hwsim radio, move to namespace via FD, verify `get_phys()` in target ns returns it |
| `test_set_wiphy_netns_pid` | Same, but using PID-based variant |
| `test_set_wiphy_netns_invalid` | Invalid wiphy index returns error |

**Note:** Tests require `mac80211_hwsim` kernel module. Should skip gracefully
if unavailable (same pattern as WireGuard tests).

## Impact on Existing API

**None.** This is purely additive — two new methods on `Connection<Nl80211>`.
No breaking changes.

## How nlink-lab Will Use It

```rust
// In deploy.rs, Step 3c: Move PHYs to namespaces

let nl_conn = Connection::<Nl80211>::new().await?;
let phys = nl_conn.get_phys().await?;

for (i, (node_name, _)) in wifi_nodes.iter().enumerate() {
    let phy = &phys[i];
    let ns_fd = node_handles[node_name].open_ns_fd()?;
    nl_conn.set_wiphy_netns(phy.index, ns_fd.as_raw_fd()).await?;
}
```

This eliminates the `iw` dependency entirely. The full Wi-Fi deployment
uses only nlink APIs + `modprobe` (for kernel module loading, which has
no netlink equivalent).
