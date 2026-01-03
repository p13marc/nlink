# Changelog

All notable changes to this project will be documented in this file.

## [0.3.1] - 2026-01-03

### Added

#### Routing Rules API
- `RuleBuilder` for creating routing rules programmatically
- `conn.get_rules()` - Get all routing rules
- `conn.get_rules_for_family(family)` - Get rules for specific address family
- `conn.add_rule(builder)` - Add a routing rule
- `conn.del_rule(builder)` - Delete a routing rule
- `conn.flush_rules(family)` - Flush all rules for a family

### Changed

#### API Cleanup
- Made `send_request()`, `send_ack()`, `send_dump()` methods `pub(crate)` (internal only)
- Removed `RouteConnection` and `GenlConnection` type aliases (use `Connection<Route>` and `Connection<Generic>` directly)
- Reorganized examples into protocol-based subdirectories (`route/`, `events/`, `namespace/`)
- Moved TC type aliases (`QdiscMessage`, `ClassMessage`, `FilterMessage`) before test module

#### Binary Refactoring
- All binary commands now use high-level APIs instead of low-level `send_*` methods
- Refactored: `address.rs`, `link.rs`, `link_add.rs`, `neighbor.rs`, `route.rs`, `rule.rs`, `tunnel.rs`, `vrf.rs`

### Fixed

- Clippy warnings (collapsible if statements, redundant closures, unnecessary casts)
- IpvlanLink no longer attempts to set MAC address (inherits from parent)

### Documentation

- Added `docs/API_CLEANUP_REPORT.md` with refactoring details and recommendations

## [0.3.0] - 2026-01-02

### Added

#### EventStream API Improvements
- `EventType` enum for convenient event type subscription
- `EventStreamBuilder::event_types(&[EventType])` method for bulk subscription
- `EventStreamBuilder::event_type(EventType)` method for single subscription
- `NetworkEvent::action()` returns "new" or "del" based on event type
- `NetworkEvent::as_link()`, `as_address()`, `as_route()`, `as_neighbor()`, `as_tc()` accessor methods
- `NetworkEvent::into_link()`, `into_address()`, `into_route()`, `into_neighbor()`, `into_tc()` consuming accessors

#### TcMessage Improvements
- `TcMessage::name` field for caching interface name
- `TcMessage::name()`, `name_or()` accessor methods
- `TcMessage::with_name()` builder method
- `TcMessage::resolve_name()`, `resolve_name_mut()` for interface name resolution

#### Error Constructor Helpers
- `Error::invalid_message()` for invalid message errors
- `Error::invalid_attribute()` for invalid attribute errors
- `Error::not_supported()` for unsupported operation errors
- `Error::interface_not_found()` for missing interface errors
- `Error::namespace_not_found()` for missing namespace errors
- `Error::qdisc_not_found()` for missing qdisc errors
- `Error::family_not_found()` for missing GENL family errors

#### TC Convenience Methods
- `apply_netem()` now includes fallback logic (tries replace, falls back to add)
- `apply_netem_by_index()` with same fallback behavior

### Changed

- `ip monitor` uses new `EventType` enum and accessor methods for cleaner code
- `tc monitor` uses `TcMessage` name helpers for interface resolution
- `tc_netem` example uses error constructor helpers

### Breaking Changes

- `TcMessage` struct now has a `name: Option<String>` field. Code constructing `TcMessage` with struct literals must add `name: None`

## [0.2.0] - 2026-01-02

### Added

#### API Improvements
- `LinkMessage::name_or(default)` helper method for cleaner interface name access
- `Connection::get_interface_names()` returns `HashMap<u32, String>` for resolving ifindex to names
- Unified all public `ifindex` types to `u32` (was mixed `i32`/`u32`)

#### New Link Types (Phase 8)
- `BareudpLink` - Bare UDP tunneling for MPLS
- `NetkitLink` - BPF-optimized virtual ethernet
- `NlmonLink` - Netlink monitor for debugging
- `VirtWifiLink` - Virtual WiFi for testing
- `VtiLink` / `Vti6Link` - Virtual Tunnel Interface for IPsec
- `Ip6GreLink` / `Ip6GretapLink` - IPv6 GRE tunnels

#### Generic Netlink Support (Phase 7)
- `GenlConnection` for Generic Netlink protocol
- WireGuard configuration via `WireguardConnection`
- `WgDevice` and `WgPeer` builders for WireGuard setup

#### Traffic Control
- **New Qdiscs**: `DrrConfig`, `QfqConfig`, `PlugConfig`, `MqprioConfig`, `TaprioConfig`, `EtfConfig`, `HfscConfig`
- **New Filters**: `CgroupFilter`, `RouteFilter`, `FlowFilter`
- **New Actions**: `ConnmarkAction`, `CsumAction`, `SampleAction`, `CtAction`, `PeditAction`
- Total: 19 qdisc types, 9 filter types, 12 action types

#### Validation
- `Validatable` trait for pre-send validation of configurations
- `ValidationResult` with errors and warnings

#### Examples
- 15 comprehensive examples in `crates/nlink/examples/`
- Examples README with usage documentation

### Changed

- Migrated to `zerocopy` crate for safe byte serialization (no unsafe code in types module)
- Improved error handling with `ValidationErrorInfo` for structured errors
- Split documentation into `docs/library.md` and `docs/cli.md`
- Updated all documentation to use `nlink` crate name

### Fixed

- Clippy warnings across the codebase
- Rustdoc HTML tag warnings
- Type consistency for `ifindex` across all message types

## [0.1.2] - 2024-12-XX

- Initial public release
- Core netlink socket and connection handling
- Link, address, route, neighbor operations
- Event monitoring (link, address, route, neighbor, TC)
- Network namespace support
- Basic TC qdisc operations
