# Binary Improvements Report

**Date:** 2026-01-04  
**Status:** Analysis Complete

## Executive Summary

Our current binaries (`ip`, `tc`, `ss`) cover most common use cases but have gaps compared to iproute2. This report identifies:
1. Missing features in existing binaries
2. New binaries we could create using our library capabilities
3. Priority recommendations

## Current Binary Coverage

### 1. `nlink-ip` Binary

**Currently Implemented:**
| Command | Subcommands | Status |
|---------|-------------|--------|
| `link` | show, add, del, set | Complete |
| `address` | show, add, del, flush | Complete |
| `route` | show, add, del, replace, get | Complete |
| `neighbor` | show, add, del, replace, flush | Complete |
| `rule` | show, add, del | Complete |
| `netns` | list, add, del, exec, identify, pids | Complete |
| `monitor` | link, address, route, neigh, all | Complete |
| `tunnel` | show, add, del, change | Complete |
| `maddress` | show | Complete |
| `vrf` | show, exec, identify, pids | Complete |
| `xfrm` | state, policy (show, flush, count) | Partial |

**Missing from iproute2:**
| Command | Description | Library Support | Priority |
|---------|-------------|-----------------|----------|
| `nexthop` | Nexthop object management | **Yes** (Plan 005) | **High** |
| `mptcp` | MPTCP endpoint management | **Yes** (Plan 009) | **High** |
| `macsec` | MACsec device configuration | **Yes** (Plan 008) | Medium |
| `sr` | Segment routing (SRv6) | **Yes** (Plan 007) | Medium |
| `addrlabel` | Address label configuration | No | Low |
| `fou` | Foo-over-UDP configuration | No | Low |
| `ila` | Identifier locator addresses | No | Low |
| `ioam` | In-situ OAM | No | Low |
| `l2tp` | L2TP tunnel management | No | Low |
| `mroute` | Multicast routing cache | No | Low |
| `mrule` | Multicast routing rules | No | Low |
| `netconf` | Network configuration monitoring | Partial | Low |
| `ntable` | Neighbor cache operation | No | Low |
| `stats` | Interface statistics groups | Partial | Low |
| `tcpmetrics` | TCP metrics management | No | Low |
| `token` | Tokenized interface identifiers | No | Low |
| `tuntap` | TUN/TAP device listing | **Yes** (feature: tuntap) | Medium |

### 2. `nlink-tc` Binary

**Currently Implemented:**
| Command | Subcommands | Status |
|---------|-------------|--------|
| `qdisc` | show, add, del, replace, change | Complete |
| `class` | show, add, del, replace, change | Complete |
| `filter` | show, add, del, replace | Complete |
| `action` | show, add, del, get | Complete |
| `monitor` | qdisc, class, filter, all | Complete |

**Qdisc Types Supported:**
- Classless: netem, fq_codel, tbf, pfifo, bfifo, red, pie, sfq, ingress, clsact, plug
- Classful: htb, prio, drr, qfq, hfsc, mqprio, taprio, etf

**Filter Types Supported:**
- u32, flower, basic, fw, bpf, cgroup, route, flow, matchall

**Action Types Supported:**
- gact, mirred, police, vlan, skbedit, nat, tunnel_key, connmark, csum, sample, ct, pedit

**Missing from iproute2:**
| Feature | Description | Library Support | Priority |
|---------|-------------|-----------------|----------|
| `chain` | Filter chain management | **Yes** (Plan 010) | **High** |
| `exec` | Execute in qdisc context | No | Low |
| Batch mode | `-b/--batch` file processing | No | Medium |
| More qdiscs | cake, choke, fq, fq_pie, gred, hhf, multiq, sfb, atm, ets | Partial | Low |

### 3. `nlink-ss` Binary

**Currently Implemented:**
| Feature | Status |
|---------|--------|
| TCP sockets | Complete |
| UDP sockets | Complete |
| Unix sockets | Complete |
| Raw sockets | Complete |
| SCTP sockets | Complete |
| MPTCP sockets | Complete |
| State filters (-l, -a) | Complete |
| Process info (-p) | Complete |
| Extended info (-e) | Complete |
| Memory info (-m) | Complete |
| TCP info (-i) | Complete |
| Address/port filters | Complete |
| JSON output | Complete |

**Missing from iproute2 ss:**
| Feature | Description | Library Support | Priority |
|---------|-------------|-----------------|----------|
| `-K/--kill` | Force close sockets | Partial | Medium |
| `-E/--events` | Event monitoring | No | Low |
| Expression filters | Complex boolean filters | No | Medium |
| DCCP sockets | Datagram Congestion Control | No | Low |
| Packet sockets | Raw packet sockets | No | Low |
| Netlink sockets | Netlink socket listing | Yes | Low |
| VSOCK sockets | Virtual socket listing | No | Low |
| TIPC sockets | TIPC socket listing | No | Low |
| XDP sockets | XDP socket listing | No | Low |
| `-s/--summary` | Socket summary statistics | Partial | Medium |
| Cgroup info | `--cgroup` option | No | Low |

---

## New Binaries We Could Create

### High Priority

#### 1. `nlink-bridge` - Bridge Management

**Rationale:** We have full library support for FDB and VLAN (Plans 002, 003).

```
nlink-bridge fdb show <bridge>
nlink-bridge fdb add <mac> dev <port> [master <bridge>] [vlan <id>] [permanent|static]
nlink-bridge fdb del <mac> dev <port>
nlink-bridge fdb flush <bridge>

nlink-bridge vlan show [dev <port>]
nlink-bridge vlan add dev <port> vid <id> [pvid] [untagged]
nlink-bridge vlan del dev <port> vid <id>

nlink-bridge link show
nlink-bridge link set dev <port> [learning on|off] [flood on|off] ...

nlink-bridge mdb show  (future)
nlink-bridge monitor
```

**Effort:** Medium (2-3 days)  
**Library coverage:** 90%

#### 2. `nlink-wg` - WireGuard Management

**Rationale:** We have full WireGuard support via Generic Netlink.

```
nlink-wg show [interface]
nlink-wg showconf <interface>
nlink-wg set <interface> [listen-port <port>] [private-key <file>] [peer <pubkey> ...]
nlink-wg genkey
nlink-wg pubkey
```

**Effort:** Medium (2-3 days)  
**Library coverage:** 80% (need key generation)

### Medium Priority

#### 3. `nlink-nh` - Nexthop Management

**Rationale:** Full nexthop support from Plan 005, currently only accessible via library.

```
nlink-nh show [id <id>]
nlink-nh add id <id> [via <gateway>] [dev <device>] [weight <weight>]
nlink-nh replace id <id> ...
nlink-nh del id <id>

nlink-nh group show [id <id>]
nlink-nh group add id <id> group <nh_id>,<weight>/... [type resilient]
nlink-nh group del id <id>
```

**Effort:** Small (1-2 days)  
**Library coverage:** 100%

#### 4. `nlink-mptcp` - MPTCP Management

**Rationale:** Full MPTCP support from Plan 009.

```
nlink-mptcp endpoint show
nlink-mptcp endpoint add <addr> [id <id>] [dev <device>] [signal] [subflow] [backup]
nlink-mptcp endpoint del id <id>
nlink-mptcp endpoint flush

nlink-mptcp limits show
nlink-mptcp limits set [subflows <n>] [add_addr_accepted <n>]
```

**Effort:** Small (1-2 days)  
**Library coverage:** 100%

#### 5. `nlink-macsec` - MACsec Management

**Rationale:** Full MACsec support from Plan 008.

```
nlink-macsec show [interface]
nlink-macsec add <interface> ...
nlink-macsec del <interface>

nlink-macsec txsa add <interface> <an> [pn <pn>] [key <key>] [on|off]
nlink-macsec txsa del <interface> <an>

nlink-macsec rxsc add <interface> <sci>
nlink-macsec rxsc del <interface> <sci>

nlink-macsec rxsa add <interface> <sci> <an> ...
nlink-macsec rxsa del <interface> <sci> <an>
```

**Effort:** Medium (2-3 days)  
**Library coverage:** 100%

### Lower Priority

#### 6. `nlink-stat` - Network Statistics

**Rationale:** We have link statistics support.

```
nlink-stat [interface]
nlink-stat -c  # continuous mode
nlink-stat -r  # show rates
nlink-stat -j  # JSON output
```

**Effort:** Small (1 day)  
**Library coverage:** 80%

#### 7. `nlink-diag` - Network Diagnostics

**Rationale:** Full diagnostics support from Plan 014.

```
nlink-diag scan <subnet>
nlink-diag connectivity <destination> [--method icmp|tcp|http]
nlink-diag bottleneck <destination>
nlink-diag path <destination>
```

**Effort:** Small (1-2 days)  
**Library coverage:** 100%

#### 8. `nlink-config` - Declarative Configuration

**Rationale:** Full declarative config support from Plan 012.

```
nlink-config show [--yaml|--json]
nlink-config diff <config-file>
nlink-config apply <config-file> [--dry-run]
nlink-config validate <config-file>
```

**Effort:** Small (1-2 days)  
**Library coverage:** 100%

---

## Improvements to Existing Binaries

### `nlink-ip` Improvements

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| Add `ip nexthop` | Nexthop object commands | Small | **High** |
| Add `ip mptcp` | MPTCP endpoint commands | Small | **High** |
| Add `ip sr` | SRv6 route commands | Medium | Medium |
| Add `ip macsec` | MACsec show command | Small | Medium |
| Add `ip tuntap` | TUN/TAP device listing | Small | Medium |
| Add `--color` | Colored output | Small | Low |
| Add `-rc` | Read config file | Medium | Low |

### `nlink-tc` Improvements

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| Add `tc chain` | Filter chain management | Small | **High** |
| Add `-b/--batch` | Batch file processing | Medium | Medium |
| Add `tc exec` | Execute in qdisc context | Medium | Low |
| Add more qdisc parsers | cake, fq, fq_pie, etc. | Medium | Low |

### `nlink-ss` Improvements

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| Add `-s/--summary` | Socket summary stats | Small | Medium |
| Add `-K/--kill` | Force close sockets | Medium | Medium |
| Add expression filters | Boolean filter expressions | Large | Low |
| Add Netlink sockets | List netlink sockets | Small | Low |

---

## Recommended Implementation Order

### Phase 1: Quick Wins (1 week)

1. **Add `ip nexthop` commands** - Library support complete
2. **Add `ip mptcp` commands** - Library support complete  
3. **Add `tc chain` commands** - Library support complete

### Phase 2: New Binaries (2 weeks)

4. **Create `nlink-bridge`** - High value, good library coverage
5. **Create `nlink-nh`** (or integrate into ip) - Full support
6. **Create `nlink-mptcp`** (or integrate into ip) - Full support

### Phase 3: Extended Features (2 weeks)

7. **Create `nlink-wg`** - Popular demand
8. **Create `nlink-diag`** - Unique value proposition
9. **Create `nlink-config`** - Infrastructure-as-code

### Phase 4: Polish (ongoing)

10. Add batch mode to tc
11. Add expression filters to ss
12. Add color output
13. Add shell completions

---

## Summary

| Category | Count | Effort |
|----------|-------|--------|
| Missing features in `ip` with library support | 4 | Small-Medium |
| Missing features in `tc` with library support | 1 | Small |
| Missing features in `ss` with library support | 2 | Small-Medium |
| New binaries possible | 8 | Medium-Large |

**Key Insight:** We have significant library capabilities (from Plans 001-014) that are not exposed via CLI. The highest ROI improvements are:

1. Adding `ip nexthop`, `ip mptcp`, and `tc chain` commands (~3 days)
2. Creating a `nlink-bridge` binary (~3 days)
3. Creating specialized tools (`nlink-diag`, `nlink-config`) that differentiate us from iproute2

The library is ahead of the binaries - we should catch up the CLI to expose existing functionality.
