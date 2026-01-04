# Plan 012: Declarative Network Configuration

## Overview

Add a declarative configuration API that lets users specify desired network state and have nlink compute and apply the necessary changes.

## Motivation

Benefits of declarative configuration:
- Infrastructure-as-code patterns
- Idempotent operations
- Automatic diff calculation
- Simpler application code
- Better error recovery

## Design

### API Design

```rust
/// Declarative network configuration.
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    links: Vec<LinkConfig>,
    addresses: Vec<AddressConfig>,
    routes: Vec<RouteConfig>,
    qdiscs: Vec<QdiscConfig>,
    rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone)]
pub struct LinkConfig {
    name: String,
    link_type: LinkType,
    state: LinkState,
    mtu: Option<u32>,
    master: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AddressConfig {
    address: IpAddr,
    prefix_len: u8,
    dev: String,
}

impl NetworkConfig {
    pub fn new() -> Self;
    
    /// Add a link configuration.
    pub fn link(self, name: &str, f: impl FnOnce(LinkBuilder) -> LinkBuilder) -> Self;
    
    /// Add an address.
    pub fn address(self, dev: &str, addr: &str) -> Result<Self>;
    
    /// Add a route.
    pub fn route(self, dst: &str, f: impl FnOnce(RouteBuilder) -> RouteBuilder) -> Result<Self>;
    
    /// Add a qdisc.
    pub fn qdisc(self, dev: &str, f: impl FnOnce(QdiscBuilder) -> QdiscBuilder) -> Self;
    
    /// Compute diff from current state.
    pub async fn diff(&self, conn: &Connection<Route>) -> Result<ConfigDiff>;
    
    /// Apply configuration.
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<ApplyResult>;
    
    /// Apply with dry-run option.
    pub async fn apply_with_options(&self, conn: &Connection<Route>, 
                                     opts: ApplyOptions) -> Result<ApplyResult>;
}

/// Difference between current and desired state.
#[derive(Debug)]
pub struct ConfigDiff {
    pub links_to_add: Vec<LinkConfig>,
    pub links_to_remove: Vec<String>,
    pub links_to_modify: Vec<(String, LinkChanges)>,
    pub addresses_to_add: Vec<AddressConfig>,
    pub addresses_to_remove: Vec<AddressConfig>,
    pub routes_to_add: Vec<RouteConfig>,
    pub routes_to_remove: Vec<RouteConfig>,
    // ...
}

impl ConfigDiff {
    /// Check if any changes are needed.
    pub fn is_empty(&self) -> bool;
    
    /// Get human-readable summary.
    pub fn summary(&self) -> String;
}

/// Apply options.
#[derive(Debug, Default)]
pub struct ApplyOptions {
    /// Don't actually make changes.
    pub dry_run: bool,
    /// Continue on errors.
    pub continue_on_error: bool,
    /// Purge unmanaged resources.
    pub purge: bool,
}
```

### Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::config::NetworkConfig;

let conn = Connection::<Route>::new()?;

// Define desired state
let config = NetworkConfig::new()
    // Links
    .link("br0", |l| l
        .bridge()
        .up()
        .stp(true)
    )
    .link("veth0", |l| l
        .veth("veth1")
        .master("br0")
        .up()
    )
    // Addresses
    .address("br0", "192.168.100.1/24")?
    .address("br0", "2001:db8::1/64")?
    // Routes
    .route("10.0.0.0/8", |r| r
        .via("192.168.100.254")
        .dev("br0")
    )?
    // QoS
    .qdisc("br0", |q| q
        .htb()
        .default_class(0x30)
    );

// Preview changes
let diff = config.diff(&conn).await?;
if !diff.is_empty() {
    println!("Changes needed:\n{}", diff.summary());
}

// Apply
let result = config.apply(&conn).await?;
println!("Applied {} changes", result.changes_made);

// Or dry-run first
let result = config.apply_with_options(&conn, ApplyOptions {
    dry_run: true,
    ..Default::default()
}).await?;
```

### YAML/TOML Support (Optional)

```rust
use nlink::config::NetworkConfig;

// Load from file
let config = NetworkConfig::from_file("network.yaml")?;

// Or from string
let yaml = r#"
links:
  - name: br0
    type: bridge
    state: up
    addresses:
      - 192.168.100.1/24

  - name: veth0
    type: veth
    peer: veth1
    master: br0
    state: up

routes:
  - destination: 10.0.0.0/8
    via: 192.168.100.254
    dev: br0
"#;

let config: NetworkConfig = serde_yaml::from_str(yaml)?;
config.apply(&conn).await?;
```

## Implementation Steps

1. Create `config` module with core types
2. Implement state diffing for links
3. Implement state diffing for addresses
4. Implement state diffing for routes
5. Implement apply logic with ordering
6. Add dry-run support
7. Optional: Add YAML/TOML support via serde

## Effort Estimate

- Core types: ~3 hours
- Link diffing: ~3 hours
- Address/route diffing: ~4 hours
- Apply logic: ~4 hours
- Dry-run/options: ~2 hours
- Serialization (optional): ~3 hours
- **Total: ~16-19 hours**
