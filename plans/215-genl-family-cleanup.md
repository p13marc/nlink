---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 215 — GENL family cleanup (M11, M12, M13, M14)
status: queued for 0.19 — MEDIUM (4 small but real bugs)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §M11, M12, M13, M14
created: 2026-05-31
---

# Plan 215 — GENL family cleanup

## 1. Why this plan exists

Four small GENL-related findings cleaned up in one pass:

- **M11** WireGuard `persistent_keepalive: Duration` silently
  caps at u16::MAX when input exceeds 65535s. Type-level fix.
- **M12** WireGuard `b64_decode_32` rejects unpadded base64.
  Interop nit.
- **M13** nl80211 SSID parser assumes element-id 0 is first IE.
  Vendor-prepended IEs hide SSID.
- **M14** Five parallel family-resolution paths (covered by Plan
  208 Phase 4 — this plan also notes here for completeness).

## 2. Phase 1 — M11 WireGuard keepalive type tightening (breaking)

**File:** `crates/nlink/src/netlink/genl/wireguard/config.rs:489-494`

Replace `Duration::from_secs(...)` argument with a `KeepaliveSecs`
newtype that holds `u16`:

```rust
/// WireGuard keepalive interval, in seconds.
///
/// The kernel field is a `u16` (max ~18.2 hours). Pre-0.19 nlink
/// accepted `Duration` and silently capped at u16::MAX — a
/// `Duration::from_secs(70_000)` became 65535 (~18.2h) instead
/// of the intended 70_000s (~19.4h, infeasible — flagged here as
/// silent truncation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveSecs(u16);

impl KeepaliveSecs {
    /// Construct a keepalive interval. Returns `None` if the
    /// value exceeds u16::MAX (65535 seconds, ~18.2 hours).
    pub const fn new(secs: u16) -> Self {
        Self(secs)
    }

    /// Try to construct from `u32`. Returns `None` on
    /// overflow.
    pub const fn try_from_u32(secs: u32) -> Option<Self> {
        if secs > u16::MAX as u32 { None } else { Some(Self(secs as u16)) }
    }

    pub fn as_secs(self) -> u16 { self.0 }

    pub fn as_duration(self) -> std::time::Duration {
        std::time::Duration::from_secs(self.0 as u64)
    }
}

impl WireguardPeerBuilder {
    pub fn persistent_keepalive(mut self, ka: KeepaliveSecs) -> Self {
        self.persistent_keepalive = Some(ka);
        self
    }
}
```

Migration: replace `Duration::from_secs(25)` with
`KeepaliveSecs::new(25)`.

## 3. Phase 2 — M12 b64_decode_32 accepts unpadded form

**File:** `crates/nlink/src/netlink/genl/wireguard/config.rs:146-149`

Replace:
```rust
if s.len() != 44 || !s.ends_with('=') || s[..43].contains('=') {
    return None;
}
```

With:
```rust
// Accept both padded (44-char, single trailing `=`) and unpadded
// (43-char) forms. WireGuard tools emit padded; some YAML/JSON
// serializers strip padding. The base64 encoding of 32 bytes is
// exactly 44 chars padded (last char is `=`); unpadded is 43.
let trimmed = s.trim_end_matches('=');
if trimmed.len() != 43 {
    return None;
}
```

Then proceed with the existing base64 decoding using the
43-char `trimmed` buffer.

Test:
```rust
#[test]
fn b64_decode_accepts_padded_and_unpadded() {
    let key = [0xab; 32];
    let padded = base64_encode_32_padded(&key);
    let unpadded = padded.trim_end_matches('=').to_string();

    assert_eq!(b64_decode_32(&padded), Some(key));
    assert_eq!(b64_decode_32(&unpadded), Some(key));
}
```

## 4. Phase 3 — M13 nl80211 SSID via TLV walker

**File:** `crates/nlink/src/netlink/genl/nl80211/connection.rs:762-773`

Replace:
```rust
NL80211_BSS_INFORMATION_ELEMENTS => {
    result.information_elements = payload.to_vec();
    // Parse SSID from IE (type 0, first element)
    if payload.len() >= 2 && payload[0] == 0 {
        let len = payload[1] as usize;
        // ...
    }
}
```

With a TLV walker:
```rust
NL80211_BSS_INFORMATION_ELEMENTS => {
    result.information_elements = payload.to_vec();
    result.ssid = parse_ssid_from_ies(payload);
}

/// Walk the 802.11 information elements and extract the SSID
/// (element ID 0). The SSID IE may not be the first element —
/// vendor-specific IEs are sometimes prepended.
fn parse_ssid_from_ies(ies: &[u8]) -> Option<String> {
    let mut offset = 0;
    while offset + 2 <= ies.len() {
        let id = ies[offset];
        let len = ies[offset + 1] as usize;
        if offset + 2 + len > ies.len() {
            // Truncated IE; bail
            return None;
        }
        if id == 0 {
            // SSID element. May be UTF-8 or non-printable bytes.
            // Lossy decode matches what `wpa_supplicant` does.
            return Some(String::from_utf8_lossy(&ies[offset+2..offset+2+len]).into_owned());
        }
        offset += 2 + len;
    }
    None
}
```

Tests:
```rust
#[test]
fn ssid_extracted_from_first_ie() {
    let ies = [0, 4, b'h', b'o', b'm', b'e'];  // id=0, len=4, "home"
    assert_eq!(parse_ssid_from_ies(&ies), Some("home".into()));
}

#[test]
fn ssid_extracted_after_vendor_specific_ie() {
    // First IE: id=221 (vendor-specific), len=3
    // Second IE: id=0 (SSID), len=4 = "home"
    let ies = [221, 3, 0xAA, 0xBB, 0xCC, 0, 4, b'h', b'o', b'm', b'e'];
    assert_eq!(parse_ssid_from_ies(&ies), Some("home".into()));
}

#[test]
fn ssid_missing_returns_none_not_garbage() {
    let ies = [221, 3, 0xAA, 0xBB, 0xCC];
    assert_eq!(parse_ssid_from_ies(&ies), None);
}

#[test]
fn truncated_ie_terminates_without_panic() {
    let ies = [0, 100, 1, 2, 3];  // claims 100 bytes, only 3 follow
    assert_eq!(parse_ssid_from_ies(&ies), None);
}
```

## 5. Phase 4 — M14 family resolution unification (covered by Plan 208)

This is already in Plan 208 Phase 4 — noted here for the
complete M-finding-to-plan mapping. No additional work in 215.

## 6. CHANGELOG entry

```markdown
### Breaking changes

- **WireGuard `persistent_keepalive` accepts `KeepaliveSecs(u16)`
  not `Duration`** (M11). The kernel field is `u16` (max
  65535 seconds ≈ 18.2 hours); the `Duration` API silently
  capped overflowing inputs. Migration:
  `persistent_keepalive(Duration::from_secs(25))` →
  `persistent_keepalive(KeepaliveSecs::new(25))`. The
  `KeepaliveSecs::try_from_u32` constructor for callers that
  hold larger types is also available.

### Fixed

- **WireGuard `b64_decode_32` accepts unpadded base64** (M12).
  Pre-0.19 the decoder required the trailing `=` even though
  base64 padding is technically optional. Now both forms work,
  fixing interop with non-strict YAML/JSON serializers.

- **nl80211 SSID parser walks the IE chain** instead of assuming
  element-id 0 is first (M13). Vendor-specific IEs (id=221)
  sometimes precede the SSID. Old code returned `None` for these
  BSSes; now correctly extracts the SSID.
```

## 7. Acceptance criteria

- [ ] `KeepaliveSecs` newtype shipped + `WireguardPeerBuilder::persistent_keepalive` signature updated
- [ ] `b64_decode_32` accepts unpadded form
- [ ] `parse_ssid_from_ies` walker shipped + 4 unit tests
- [ ] CHANGELOG entries
- [ ] Migration guide §"Plan 215" — short note on KeepaliveSecs

## 8. Effort estimate

| Phase | Time |
|---|---|
| Phase 1 — KeepaliveSecs newtype | 1.5 h |
| Phase 2 — b64 unpadded | 30 min |
| Phase 3 — SSID walker | 1 h |
| Tests + CHANGELOG | 1 h |
| **Total** | **~4 h** |

## 9. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 1 breaking + 2 fixed entries |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | §"Plan 215" |
| `crates/nlink/src/netlink/genl/wireguard/config.rs` | KeepaliveSecs + b64 decode |
| `crates/nlink/src/netlink/genl/nl80211/connection.rs` | SSID walker |
| `crates/nlink/src/netlink/genl/wireguard/mod.rs` | re-export KeepaliveSecs |

End of plan.
