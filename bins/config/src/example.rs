//! Example command - generate example configuration files.

use clap::{Args, ValueEnum};
use nlink::netlink::Result;

#[derive(Args)]
pub struct ExampleArgs {
    /// Show full example with all features
    #[arg(long)]
    pub full: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "yaml")]
    pub format: OutputFormat,

    /// Example type to generate
    #[arg(short, long, value_enum, default_value = "basic")]
    pub example: ExampleType,
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Yaml,
    Json,
}

#[derive(Clone, ValueEnum)]
pub enum ExampleType {
    /// Basic network setup
    Basic,
    /// Bridge with VLANs
    Bridge,
    /// VXLAN overlay
    Vxlan,
    /// Traffic shaping
    Qos,
    /// Container networking
    Container,
}

pub fn run(args: ExampleArgs) -> Result<()> {
    let example = if args.full {
        FULL_EXAMPLE
    } else {
        match args.example {
            ExampleType::Basic => BASIC_EXAMPLE,
            ExampleType::Bridge => BRIDGE_EXAMPLE,
            ExampleType::Vxlan => VXLAN_EXAMPLE,
            ExampleType::Qos => QOS_EXAMPLE,
            ExampleType::Container => CONTAINER_EXAMPLE,
        }
    };

    match args.format {
        OutputFormat::Yaml => {
            println!("{}", example);
        }
        OutputFormat::Json => {
            // Convert YAML to JSON
            let value: serde_yaml::Value = serde_yaml::from_str(example).map_err(|e| {
                nlink::netlink::Error::InvalidMessage(format!("YAML parse failed: {}", e))
            })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).map_err(|e| {
                    nlink::netlink::Error::InvalidMessage(format!(
                        "JSON serialization failed: {}",
                        e
                    ))
                })?
            );
        }
    }

    Ok(())
}

const BASIC_EXAMPLE: &str = r#"# Basic network configuration
# This example shows a simple bridge with a veth pair

links:
  # Create a bridge
  - name: br0
    kind: bridge
    state: up
    mtu: 1500

  # Create a veth pair and attach one end to the bridge
  - name: veth0
    kind: veth
    state: up
    master: br0
    options:
      peer: veth1

addresses:
  # Assign an IP to the bridge
  - dev: br0
    address: 10.0.0.1/24

routes:
  # Add a route via the bridge
  - destination: 10.1.0.0/16
    gateway: 10.0.0.254
    dev: br0
"#;

const BRIDGE_EXAMPLE: &str = r#"# Bridge with VLAN filtering
# This example shows a bridge with VLAN-aware configuration

links:
  # Create a VLAN-aware bridge
  - name: br0
    kind: bridge
    state: up
    options:
      vlan_filtering: true
      stp_state: 1

  # Bridge ports
  - name: veth0
    kind: veth
    state: up
    master: br0
    options:
      peer: veth1

  - name: veth2
    kind: veth
    state: up
    master: br0
    options:
      peer: veth3

addresses:
  # Management address on the bridge
  - dev: br0
    address: 192.168.1.1/24
    label: br0:mgmt

# Note: VLAN configuration on bridge ports requires
# additional commands not shown here. Use:
#   bridge vlan add vid 100 dev veth0
#   bridge vlan add vid 100 dev veth2 pvid untagged
"#;

const VXLAN_EXAMPLE: &str = r#"# VXLAN overlay network
# This example shows a VXLAN tunnel configuration

links:
  # VXLAN tunnel endpoint
  - name: vxlan100
    kind: vxlan
    state: up
    options:
      vni: 100
      local: 192.168.1.1
      group: 239.1.1.1
      port: 4789
      ttl: 64

  # Bridge for the overlay
  - name: br-overlay
    kind: bridge
    state: up

  # Attach VXLAN to bridge
  - name: vxlan100
    master: br-overlay

addresses:
  # Overlay network address
  - dev: br-overlay
    address: 10.200.0.1/24

routes:
  # Route overlay traffic
  - destination: 10.200.0.0/16
    dev: br-overlay
"#;

const QOS_EXAMPLE: &str = r#"# Traffic shaping with HTB
# This example shows hierarchical token bucket configuration

links:
  - name: eth0
    state: up

qdiscs:
  # Root HTB qdisc
  - dev: eth0
    parent: root
    kind: htb
    handle: "1:"
    options:
      default: "30"

# Note: Class and filter configuration requires
# additional commands. Example:
#
# Add root class (total bandwidth):
#   tc class add dev eth0 parent 1: classid 1:1 htb rate 1gbit ceil 1gbit
#
# Add leaf classes:
#   tc class add dev eth0 parent 1:1 classid 1:10 htb rate 100mbit ceil 500mbit prio 1
#   tc class add dev eth0 parent 1:1 classid 1:20 htb rate 200mbit ceil 800mbit prio 2
#   tc class add dev eth0 parent 1:1 classid 1:30 htb rate 50mbit prio 3
#
# Add filters:
#   tc filter add dev eth0 parent 1: protocol ip flower ip_proto tcp dst_port 80 classid 1:10
#   tc filter add dev eth0 parent 1: protocol ip flower ip_proto tcp dst_port 443 classid 1:20
"#;

const CONTAINER_EXAMPLE: &str = r#"# Container networking
# This example shows a typical container network setup

links:
  # Bridge for containers
  - name: docker0
    kind: bridge
    state: up
    mtu: 1500
    options:
      stp_state: 0

  # Veth pair for a container
  # One end (veth-c1) goes into the container namespace
  # Other end (veth-c1-br) attaches to the bridge
  - name: veth-c1-br
    kind: veth
    state: up
    master: docker0
    options:
      peer: veth-c1

addresses:
  # Bridge gateway address
  - dev: docker0
    address: 172.17.0.1/16

routes:
  # Container network is directly connected
  # No explicit route needed for 172.17.0.0/16

# Note: The container's veth endpoint (veth-c1) would be
# moved into the container's network namespace with:
#   ip link set veth-c1 netns <container-pid>
#
# Inside the container:
#   ip addr add 172.17.0.2/16 dev veth-c1
#   ip link set veth-c1 up
#   ip route add default via 172.17.0.1
"#;

const FULL_EXAMPLE: &str = r#"# Full network configuration example
# This shows all supported configuration options

links:
  # Bridge with all options
  - name: br0
    kind: bridge
    state: up
    mtu: 9000
    options:
      vlan_filtering: true
      stp_state: 1

  # Veth pair
  - name: veth0
    kind: veth
    state: up
    master: br0
    options:
      peer: veth1

  # VXLAN tunnel
  - name: vxlan100
    kind: vxlan
    state: up
    options:
      vni: 100
      local: 192.168.1.1
      remote: 192.168.1.2
      port: 4789
      ttl: 64

  # Dummy interface for routing
  - name: dummy0
    kind: dummy
    state: up

  # VLAN interface
  - name: eth0.100
    kind: vlan
    state: up
    options:
      id: 100
      link: eth0

  # Macvlan interface
  - name: macvlan0
    kind: macvlan
    state: up
    options:
      link: eth0
      mode: bridge

addresses:
  # Primary bridge address
  - dev: br0
    address: 10.0.0.1/24
    label: br0:primary

  # Secondary address
  - dev: br0
    address: 10.0.0.2/24
    label: br0:secondary

  # Dummy for anycast
  - dev: dummy0
    address: 192.168.100.1/32

  # IPv6 address
  - dev: br0
    address: "2001:db8::1/64"

routes:
  # Default route with metric
  - destination: default
    gateway: 10.0.0.254
    dev: br0
    metric: 100

  # Static route
  - destination: 10.1.0.0/16
    gateway: 10.0.0.1
    dev: br0

  # Blackhole route
  - destination: 10.99.0.0/16
    type: blackhole

  # Route with specific table
  - destination: 172.16.0.0/12
    gateway: 10.0.0.253
    dev: br0
    table: "100"

rules:
  # Source-based routing
  - priority: 100
    from: 10.0.0.0/8
    table: "100"

  # Fwmark-based routing
  - priority: 200
    fwmark: "0x100"
    table: "200"

  # Blackhole rule
  - priority: 300
    from: 192.168.99.0/24
    action: blackhole

qdiscs:
  # HTB qdisc for traffic shaping
  - dev: eth0
    parent: root
    kind: htb
    handle: "1:"
    options:
      default: "30"

  # Netem for testing
  - dev: veth0
    parent: root
    kind: netem
    options:
      delay_ms: 100
      loss_percent: 1.0

  # FQ_CODEL for fair queueing
  - dev: br0
    parent: root
    kind: fq_codel
"#;
