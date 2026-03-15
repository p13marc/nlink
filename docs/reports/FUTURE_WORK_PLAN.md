# Future Work Plan

Remaining work items not yet implemented. Items already completed have been removed.

## High Priority

### 1. CI Integration for Integration Tests

Add GitHub Actions workflow with privileged containers to run integration tests automatically.

**Tasks:**
- [ ] Create `.github/workflows/integration-tests.yml`
- [ ] Use Docker with `--privileged` or rootless containers with user namespaces
- [ ] Run tests with `--test-threads=1` to avoid namespace collisions
- [ ] Consider using `netns` cleanup in CI to prevent resource leaks
- [ ] Add clippy, fmt, and feature matrix checks

**Complexity:** Medium

---

## Medium Priority

### 2. MACsec Enhancements

Complete MACsec implementation with device management and statistics.

**Tasks:**
- [ ] Device creation/deletion via rtnetlink (IFLA_INFO_KIND "macsec")
- [ ] SecY configuration updates (cipher suite, validation mode)
- [ ] Statistics retrieval (TX/RX packet counts, SA stats)
- [ ] Hardware offload configuration

**Complexity:** Medium-High

---

### 3. SRv6 Advanced Features

Extend SRv6 support with advanced features.

**Tasks:**
- [ ] SRv6 with HMAC verification
- [ ] SRv6 Policy (multiple color/endpoint combinations)
- [ ] uSID (micro-SID) support
- [ ] SRv6 counters and statistics

**Complexity:** High

---

## Low Priority

### 4. Additional Edge Case Tests

Expand test coverage for edge cases.

**Tasks:**
- [ ] Error condition tests (permission denied, device busy)
- [ ] Race condition tests for concurrent operations
- [ ] Large-scale tests (many interfaces, routes, etc.)

**Complexity:** Low

---

### 5. `ss` Binary Remaining Features

**Tasks:**
- [ ] `-K/--kill` mode (socket destroy)
- [ ] Expression filters
- [ ] DCCP/VSOCK/TIPC socket types

**Complexity:** Medium

---

## Notes

- Some features (uSID, SRv6 Policy) may require newer kernel versions
- Hardware offload features require specific NIC support for testing
