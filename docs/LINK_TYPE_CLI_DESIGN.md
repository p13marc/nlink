# Link Type CLI Design

## Problem Statement

The current `ip link add` implementation uses manual argument parsing for link type-specific options:

```bash
ip link add test0 --type dummy
ip link add eth0.100 --type vlan --link eth0 --vlan-id 100
```

This approach has several issues:

1. **No type-specific help** - `--help` shows all options for all types
2. **Manual parsing** - Duplicates clap's functionality, error-prone
3. **No validation** - Type-specific required options aren't enforced by clap
4. **Poor discoverability** - Users don't know what options each type supports

## Proposed Solutions

### Option A: Link Type as Subcommand

```bash
ip link add dummy test0
ip link add vlan eth0.100 --link eth0 --id 100
ip link add bridge br0 --stp --forward-delay 4
ip link add bond bond0 --mode 802.3ad --miimon 100
ip link add veth veth0 --peer veth1
ip link add vxlan vxlan0 --vni 100 --remote 10.0.0.1 --dstport 4789
```

**Pros:**
- Native clap subcommands with derive macros
- Type-specific `--help`: `ip link add vlan --help`
- Compile-time validation of required args per type
- Clean, idiomatic Rust/clap code
- Better shell completion support

**Cons:**
- Different from iproute2 syntax
- Name comes after type (minor learning curve)

**Implementation:**

```rust
#[derive(Subcommand)]
enum LinkAddType {
    /// Create a dummy interface
    Dummy {
        /// Interface name
        name: String,
        #[command(flatten)]
        common: CommonLinkArgs,
    },
    
    /// Create a VLAN interface
    Vlan {
        /// Interface name
        name: String,
        /// Parent interface
        #[arg(long)]
        link: String,
        /// VLAN ID (1-4094)
        #[arg(long)]
        id: u16,
        #[command(flatten)]
        common: CommonLinkArgs,
    },
    
    /// Create a bridge
    Bridge {
        name: String,
        #[arg(long)]
        stp: bool,
        #[arg(long)]
        forward_delay: Option<u32>,
        #[command(flatten)]
        common: CommonLinkArgs,
    },
    // ... more types
}

#[derive(Args)]
struct CommonLinkArgs {
    #[arg(long)]
    mtu: Option<u32>,
    #[arg(long)]
    address: Option<String>,
    #[arg(long)]
    txqlen: Option<u32>,
}
```

---

### Option B: Flattened Options with Runtime Validation

Keep current syntax but flatten all type options:

```bash
ip link add test0 --type dummy
ip link add eth0.100 --type vlan --link eth0 --id 100
```

**Pros:**
- Closer to iproute2 syntax
- Single flat argument struct

**Cons:**
- `--help` shows all options for all types (confusing)
- Runtime validation needed (type X requires option Y)
- Many optional fields, most unused per invocation
- No compile-time guarantees

**Implementation:**

```rust
#[derive(Args)]
struct LinkAddArgs {
    name: String,
    #[arg(long = "type")]
    link_type: String,
    
    // Common
    #[arg(long)]
    mtu: Option<u32>,
    #[arg(long)]
    link: Option<String>,
    
    // VLAN
    #[arg(long)]
    id: Option<u16>,
    
    // VXLAN
    #[arg(long)]
    vni: Option<u32>,
    #[arg(long)]
    remote: Option<String>,
    
    // Bridge
    #[arg(long)]
    stp: bool,
    
    // Bond
    #[arg(long)]
    mode: Option<String>,
    #[arg(long)]
    miimon: Option<u32>,
    
    // ... 50+ more options across all types
}
```

---

### Option C: Two-Phase Parsing

Parse common args with clap, then type-specific args separately:

```bash
ip link add test0 --type vlan -- --link eth0 --id 100
```

**Pros:**
- Separates concerns cleanly
- Each type can have its own Args struct

**Cons:**
- Awkward `--` separator in CLI
- Complex parsing logic
- Non-standard UX

---

### Option D: Hybrid - Type Flag with Subcommand-like Behavior

Use clap's `subcommand_required = false` with external subcommands:

```bash
ip link add --type vlan eth0.100 --link eth0 --id 100
ip link add --type dummy test0
```

**Pros:**
- Keeps `--type` flag familiar to iproute2 users
- Can still have type-specific help via `ip link add --type vlan --help`

**Cons:**
- More complex clap configuration
- Not as clean as pure subcommands

---

## Recommendation

**Option A (Subcommands)** is recommended because:

1. **Idiomatic** - Standard clap pattern, well-supported
2. **Type-safe** - Each type has compile-time validated args
3. **Discoverable** - `ip link add --help` lists all types, `ip link add vlan --help` shows vlan options
4. **Maintainable** - Adding new types is just adding enum variants
5. **Consistent** - Other modern CLI tools use this pattern (e.g., `docker network create bridge`)

The syntax difference from iproute2 is acceptable since we explicitly decided this is not a drop-in replacement.

## Example Help Output with Option A

```
$ ip link add --help
Create a virtual network interface

Usage: ip link add <COMMAND>

Commands:
  dummy     Create a dummy interface
  veth      Create a virtual ethernet pair
  bridge    Create a bridge device
  bond      Create a bonding device
  vlan      Create a VLAN interface
  vxlan     Create a VXLAN interface
  macvlan   Create a MACVLAN interface
  ipvlan    Create an IPVLAN interface
  vrf       Create a VRF device
  gre       Create a GRE tunnel
  wireguard Create a WireGuard interface

$ ip link add vlan --help
Create a VLAN interface

Usage: ip link add vlan [OPTIONS] --link <LINK> --id <ID> <NAME>

Arguments:
  <NAME>  Interface name

Options:
      --link <LINK>      Parent interface
      --id <ID>          VLAN ID (1-4094)
      --protocol <PROTO> VLAN protocol [default: 802.1q]
      --mtu <MTU>        Maximum transmission unit
      --address <MAC>    MAC address
  -h, --help             Print help
```

## Migration Path

1. Remove incomplete `nlink-link` crate with manual parsing
2. Add `LinkAddType` enum to `bins/ip/src/commands/link.rs`
3. Implement each link type as an enum variant with its own args
4. Keep netlink building logic in helper functions (could move to library later)
5. Update README with new syntax examples

## Questions for Review

1. Is the syntax change from `--type X` to subcommands acceptable?
2. Should we keep `nlink-link` as a separate crate for the netlink building logic?
3. Any link types that should be prioritized for initial implementation?
4. Should we support both syntaxes during a transition period?
