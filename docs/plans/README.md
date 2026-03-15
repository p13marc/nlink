# Plans

Implementation plans for nlink features and improvements.

## Plan Index

### Tier 1: Quick Wins (Days)

| Plan | Target | Description | Effort |
|------|--------|-------------|--------|
| [028](028-tunnel-link-types.md) | Library | GRE, IPIP, SIT tunnel link types | 1 day |
| [035](035-code-quality.md) | Library/Bins | SAFETY comments, optional serde_json, zerocopy migration | 1 day |

### Tier 2: Medium-Term (Weeks)

| Plan | Target | Description | Effort |
|------|--------|-------------|--------|
| [030](030-netlink-batching.md) | Library | Bulk operations via batched sendmsg | 1.5 weeks |
| [031](031-bond-support.md) | Library | Complete bond mode/slave management | 2 days |
| [032](032-operation-timeouts.md) | Library | Configurable timeouts for netlink ops | 1 day |
| [034](034-bpf-tc-attachment.md) | Library | BPF program attachment to TC hooks | 1 day |
| [026](026-ss-improvements.md) | Binary | Kill mode, expression filters, DCCP/VSOCK/TIPC | 1 day |

### Tier 3: Strategic (Months)

| Plan | Target | Description | Effort |
|------|--------|-------------|--------|
| [033](033-nftables.md) | Library | nftables firewall support (no Rust lib has this) | 4+ weeks |
| [036](036-nl80211-wifi.md) | Library | WiFi configuration via nl80211 GENL | 1-3 weeks |
| [037](037-devlink.md) | Library | Hardware device management via devlink GENL | 1-2 weeks |

## Reference Documents

| File | Description |
|------|-------------|
| [GUIDELINES.md](GUIDELINES.md) | Implementation guidelines (zerocopy vs winnow, coding patterns) |

## Completed Plans (removed)

Plans 000-025 have been implemented and their files removed.
See git history for reference.
