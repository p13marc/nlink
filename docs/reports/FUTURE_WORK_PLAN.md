# Future Work Plan

This document consolidates future work items identified in completion reports.
Items are organized by priority and complexity.

## High Priority

### 1. CI Integration for Integration Tests
**Source:** [011-integration-tests.md](011-integration-tests.md)

Add GitHub Actions workflow with privileged containers to run integration tests automatically.

**Tasks:**
- [ ] Create `.github/workflows/integration-tests.yml`
- [ ] Use Docker with `--privileged` or rootless containers with user namespaces
- [ ] Run tests with `--test-threads=1` to avoid namespace collisions
- [ ] Consider using `netns` cleanup in CI to prevent resource leaks

**Complexity:** Medium

---

### 2. HFSC and DRR Class Builders
**Source:** [004-htb-class-builder.md](004-htb-class-builder.md)

Add typed builders for other classful qdisc class types.

**Tasks:**
- [ ] `HfscClassConfig` - HFSC service curve classes (rt, ls, ul curves)
- [ ] `DrrClassConfig` - DRR quantum configuration
- [ ] `QfqClassConfig` - QFQ weight configuration

**Complexity:** Medium

---

### 3. FDB Event Monitoring
**Source:** [002-bridge-fdb.md](002-bridge-fdb.md)

Add support for monitoring FDB changes via netlink multicast.

**Tasks:**
- [ ] Subscribe to RTM_NEWNEIGH/RTM_DELNEIGH with AF_BRIDGE
- [ ] Add `FdbEvent` variant to `NetworkEvent` enum
- [ ] Add `RtnetlinkGroup::BridgeFdb` or similar

**Complexity:** Low-Medium

---

## Medium Priority

### 4. Bridge VLAN Tunneling
**Source:** [003-bridge-vlan.md](003-bridge-vlan.md)

Support VLAN-to-VNI mapping for VXLAN bridges.

**Tasks:**
- [ ] IFLA_BRIDGE_VLAN_TUNNEL_INFO parsing
- [ ] `BridgeVlanTunnelBuilder` for VLAN-VNI mapping
- [ ] Per-VLAN STP state configuration

**Complexity:** Medium

---

### 5. MACsec Enhancements
**Source:** [008-macsec.md](008-macsec.md)

Complete MACsec implementation with device management and statistics.

**Tasks:**
- [ ] Device creation/deletion via rtnetlink (IFLA_INFO_KIND "macsec")
- [ ] SecY configuration updates (cipher suite, validation mode)
- [ ] Statistics retrieval (TX/RX packet counts, SA stats)
- [ ] Hardware offload configuration

**Complexity:** Medium-High

---

### 6. MPTCP Enhancements
**Source:** [009-mptcp.md](009-mptcp.md)

Extend MPTCP support with per-connection management.

**Tasks:**
- [ ] Per-connection endpoint management via token
- [ ] Subflow create/destroy operations
- [ ] MPTCP socket statistics integration with sockdiag

**Complexity:** Medium-High

---

### 7. SRv6 Advanced Features
**Source:** [007-srv6.md](007-srv6.md)

Extend SRv6 support with advanced features.

**Tasks:**
- [ ] SRv6 with HMAC verification
- [ ] SRv6 Policy (multiple color/endpoint combinations)
- [ ] uSID (micro-SID) support
- [ ] SRv6 counters and statistics

**Complexity:** High

---

## Low Priority

### 8. Additional Edge Case Tests
**Source:** [011-integration-tests.md](011-integration-tests.md)

Expand test coverage for edge cases.

**Tasks:**
- [ ] Error condition tests (permission denied, device busy)
- [ ] Race condition tests for concurrent operations
- [ ] Large-scale tests (many interfaces, routes, etc.)

**Complexity:** Low

---

## Implementation Order Recommendation

1. **CI Integration** - Enables automated testing for all future work
2. **FDB Event Monitoring** - Small, self-contained feature
3. **HFSC/DRR Class Builders** - Extends existing pattern
4. **Bridge VLAN Tunneling** - Useful for VXLAN deployments
5. **MACsec Enhancements** - Completes the MACsec implementation
6. **MPTCP Enhancements** - Completes the MPTCP implementation
7. **SRv6 Advanced Features** - Complex, requires kernel testing

---

## Notes

- Items from [001-tc-class-api.md](001-tc-class-api.md) regarding typed HTB class builder have been completed in Plan 004
- Some features (uSID, SRv6 Policy) may require newer kernel versions
- Hardware offload features require specific NIC support for testing
