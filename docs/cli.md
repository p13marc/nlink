# nlink CLI Tools

The CLI binaries serve as proof-of-concept demonstrations of the
`nlink` library — the library is the deliverable; the binaries show
it in use. They are **not** drop-in replacements for iproute2 /
iw / ethtool.

Most binaries are named after the system tool they mirror (`ip`,
`tc`, `ss`, `nft`, `bridge`, `wg`, `devlink`, `wifi`); two are
`nlink-` prefixed to avoid shadowing (`nlink-config`,
`nlink-ethtool`). The cargo package is always `nlink-<tool>`
(e.g. `cargo run -p nlink-ip -- link show`).

Coverage below: [`ip`](#ip), [`tc`](#tc), [`ss`](#ss),
[`nft`](#nft), [`bridge`](#bridge), [`wg`](#wg),
[`nlink-config`](#nlink-config), [`devlink`](#devlink),
[`nlink-ethtool`](#nlink-ethtool), [`wifi`](#wifi).

## ip

Network interface and routing management.

### Link Operations

```bash
# List interfaces
ip link show

# Create interfaces
ip link add dummy test0
ip link add veth veth0 --peer veth1
ip link add bridge br0 --stp --vlan-filtering
ip link add bond bond0 --mode 802.3ad --miimon 100
ip link add vlan eth0.100 --link eth0 --id 100
ip link add vxlan vxlan0 --vni 100 --remote 10.0.0.1 --dstport 4789

# Delete/modify interfaces
ip link del test0
ip link set eth0 --up --mtu 9000
```

### Address Operations

```bash
ip addr show
ip addr add 192.168.1.1/24 -d eth0
ip addr del 192.168.1.1/24 -d eth0
```

### Route Operations

```bash
ip route show
ip route add 10.0.0.0/8 --via 192.168.1.1
ip route del 10.0.0.0/8
ip route get 8.8.8.8
```

### Neighbor Operations

```bash
ip neigh show
ip neigh add 192.168.1.2 --lladdr 00:11:22:33:44:55 -d eth0
ip neigh del 192.168.1.2 -d eth0
ip neigh flush dev eth0
```

### Policy Routing Rules

```bash
ip rule show
ip rule add --from 10.0.0.0/8 --table 100 --priority 1000
ip rule add --fwmark 0x100 --table 200
ip rule del --priority 1000
```

### Monitoring

```bash
ip monitor all
ip monitor link address --timestamp
ip monitor -j  # JSON output
```

### Network Namespaces

```bash
ip netns list
ip netns add myns
ip netns exec myns ip link show
ip netns del myns
ip netns identify $$
ip netns pids myns
ip netns monitor
```

### Tunnels

```bash
ip tunnel show
ip tunnel add gre1 --mode gre --remote 10.0.0.1 --local 10.0.0.2 --ttl 64
ip tunnel add tun0 --mode ipip --remote 192.168.1.1 --local 192.168.1.2
ip tunnel change gre1 --remote 10.0.0.3
ip tunnel del gre1
```

### Other Commands

```bash
# Multicast addresses
ip maddress show
ip maddress show dev eth0

# VRF
ip vrf show
ip vrf exec vrf0 ping 10.0.0.1
ip vrf identify $$
ip vrf pids vrf0

# XFRM/IPSec
ip xfrm state show
ip xfrm state count
ip xfrm policy show
ip xfrm policy count
```

## tc

Traffic control (qdisc, class, filter).

### Qdisc Operations

```bash
# List qdiscs
tc qdisc show
tc qdisc show dev eth0

# Add qdiscs
tc qdisc add dev eth0 --parent root htb default 10 r2q 10
tc qdisc add dev eth0 --parent root fq_codel limit 10000 target 5ms interval 100ms ecn
tc qdisc add dev eth0 --parent root tbf rate 1mbit burst 32kb limit 100kb
tc qdisc add dev eth0 --parent root prio bands 3
tc qdisc add dev eth0 --parent root sfq perturb 10 limit 127
tc qdisc add dev eth0 --parent root choke limit 1000k min 50k max 150k ecn
tc qdisc add dev eth0 --parent root pfifo_fast   # restore the kernel default
tc qdisc add dev eth0 --parent root gred setup DPs 8 default 2 grio   # GRED setup phase

# Replace/change qdiscs
tc qdisc replace dev eth0 --parent root fq_codel limit 5000
tc qdisc change dev eth0 --parent root fq_codel target 10ms

# Delete qdiscs
tc qdisc del dev eth0 --parent root
```

### Network Emulation (netem)

```bash
tc qdisc add dev eth0 --parent root netem delay 100ms 10ms 25%
tc qdisc add dev eth0 --parent root netem loss 1% 25%
tc qdisc add dev eth0 --parent root netem duplicate 1%
tc qdisc add dev eth0 --parent root netem corrupt 0.1%
tc qdisc add dev eth0 --parent root netem reorder 25% 50% gap 5
tc qdisc add dev eth0 --parent root netem rate 1mbit
tc qdisc add dev eth0 --parent root netem delay 100ms loss 1% duplicate 0.5%
```

### Class Operations

```bash
tc class show
tc class show dev eth0

# HTB classes
tc class add dev eth0 --parent 1: --classid 1:10 htb rate 10mbit ceil 100mbit prio 1
tc class add dev eth0 --parent 1: --classid 1:20 htb rate 5mbit ceil 50mbit burst 15k
```

### Filter Operations

```bash
tc filter show
tc filter show dev eth0
```

### Monitoring

```bash
tc monitor all
tc monitor qdisc class --timestamp
tc monitor -j  # JSON output
```

## ss

Socket statistics over `NETLINK_SOCK_DIAG`. Flag-driven (no
subcommands); a trailing ss-style filter expression is accepted.

```bash
ss -t                       # connected TCP sockets
ss -tln                     # listening TCP, numeric (no name resolution)
ss -tp                      # with the owning process (inode → /proc)
ss -u / ss -x / ss -w       # UDP / Unix / raw sockets
ss -0                       # AF_PACKET sockets
ss -a                       # all states; -4 / -6 to restrict family

# Filters: typed --sport/--dport/--src/--dst, or an ss-style expression
ss -tn 'sport = :22'
ss -tn --dst 10.0.0.0/8 --dport 443

# Detail blocks (gated, mirrored in JSON): -i info, -m memory, -e extended, -o timer
ss -tim
ss -tj -i                   # JSON; honors the display flags
ss -s                       # summary counters
```

## nft

nftables over `NETLINK_NETFILTER`. Imperative ops plus a declarative
desired-state path (see the
[declarative-config recipe](recipes/nftables-declarative-config.md)).

```bash
nft list tables
nft list chains
nft list rules inet filter input      # decoded rule expressions
nft list sets inet

# Imperative mutation
nft add table inet filter
nft add chain inet filter input hook input priority 0 policy drop
nft add rule inet filter input tcp dport 22 accept
nft delete table inet filter
nft flush ruleset

# Imperative atomic batch from a file (every line commits or none do)
nft apply ops.nft

# Declarative desired-state reconcile (diff → minimal apply)
nft diff fw.nft                       # preview only
nft reconcile fw.nft                  # apply the minimal delta
nft reconcile fw.nft --dry-run        # same as `diff`
```

## bridge

Bridge forwarding database, VLAN filtering, ports, and multicast.

```bash
bridge fdb show
bridge fdb show brport eth0
bridge fdb add 00:11:22:33:44:55 dev eth0 master
bridge fdb add 00:11:22:33:44:55 dev eth0 --extern-learn   # NTF_EXT_LEARNED

bridge vlan show                      # JSON output sorts by ifindex
bridge vlan add dev eth0 vid 100 pvid untagged

bridge link set dev eth0 ...          # per-port options (learning, flood, ...)
bridge mdb show
bridge monitor                        # live FDB/MDB events
```

## wg

WireGuard over Generic Netlink.

```bash
wg show                               # all interfaces + peers
wg showconf wg0                       # wg-quick format (reveals private key)
wg set wg0 --peer <pubkey> --allowed-ips 10.0.0.0/24 --endpoint host:51820

# Config files (kernel-level [Interface] + [Peer] format)
wg setconf wg0 wg0.conf                # replace
wg addconf wg0 extra-peers.conf        # additive (keeps existing peers)
wg syncconf wg0 wg0.conf               # reconcile with bounded retry

wg genkey | wg pubkey                  # key generation
wg genpsk
wg watch                               # peer/handshake/endpoint changes
```

## nlink-config

Declarative whole-host network state (links + addresses + routes +
qdiscs) — the `NetworkConfig` diff/apply engine as a CLI. See the
[library guide](library.md#declarative-network-configuration).

```bash
nlink-config example                   # emit a sample config (YAML; --format json)
nlink-config capture > current.yaml    # snapshot live state to a file
nlink-config diff desired.yaml         # preview the changes apply would make
nlink-config apply desired.yaml        # reconcile the kernel to the file
nlink-config apply desired.yaml --dry-run
nlink-config apply desired.yaml --reconcile   # bounded retry on contention
```

## devlink

Device-management over the `devlink` Generic Netlink family.

```bash
devlink dev                            # list devlink devices
devlink port                           # ports (incl. split/unsplit, SR-IOV functions)
devlink info                           # firmware + driver versions
devlink param                          # device parameters (type-aware set)
devlink rate                           # port-function / scheduler-node shaping
devlink sb / trap / region / resource  # shared buffers, traps, regions, resources
devlink monitor                        # live devlink events
```

## nlink-ethtool

NIC settings + statistics over the `ethtool` Generic Netlink family.
Subcommands carry the classic `ethtool` short flags as aliases.

```bash
nlink-ethtool eth0                     # link settings (default action)
nlink-ethtool -k eth0                  # features / offloads
nlink-ethtool -S eth0                  # standardized IEEE 802.3 / RMON stats
nlink-ethtool -g eth0 / -l eth0        # ring sizes / channel counts
nlink-ethtool wol eth0                 # Wake-on-LAN settings
nlink-ethtool set-wol eth0 magic       # enable WoL on magic packet (or `none` to disable)
nlink-ethtool eee eth0 / fec eth0      # Energy-Efficient Ethernet / FEC

# Setters
nlink-ethtool -K eth0 tso off gro on   # toggle features
nlink-ethtool -s eth0 speed 1000 duplex full autoneg on
nlink-ethtool monitor                  # live ethtool events
```

## wifi

Wireless (nl80211) over Generic Netlink.

```bash
wifi list                              # wireless interfaces
wifi show wlan0                        # detailed interface info
wifi scan wlan0                        # trigger a scan + show results
wifi results wlan0                     # cached results, no new scan
wifi station wlan0                     # connection / signal info
wifi del-station wlan0 <mac>           # kick a station (AP mode)
wifi connect wlan0 <ssid> --auth sae   # --auth open|shared|sae|ft|eap; --bssid/--freq to pin
wifi disconnect wlan0
wifi reg / wifi reg US                 # show / set regulatory domain
wifi powersave wlan0 [on|off]
wifi monitor                           # scan/connect/disconnect/regulatory events
```

## Building

Requires Rust 1.95+ (edition 2024).

```bash
# Build all
cargo build --release

# Run commands — the cargo package is always `nlink-<tool>`
cargo run --release -p nlink-ip -- link show
cargo run --release -p nlink-tc -- qdisc show
cargo run --release -p nlink-nft -- list tables
```
