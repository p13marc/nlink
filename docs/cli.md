# nlink CLI Tools

The CLI binaries serve as proof-of-concept demonstrations. They are not drop-in replacements for iproute2.

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

## Building

Requires Rust 1.85+ (edition 2024).

```bash
# Build all
cargo build --release

# Run commands
cargo run --release -p ip -- link show
cargo run --release -p tc -- qdisc show
```
