---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: `Verdict::Jump`/`Goto` typed `ChainName` — close the bare-String hazard
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_API.md](../AUDIT_API.md) Finding A20
created: 2026-06-04
---

# Plan 230 — `Verdict::Jump`/`Goto` typed `ChainName`

## 1. Why this plan exists

`nftables::types::Verdict::Jump(String)` and
`Verdict::Goto(String)` use bare `String` for chain references:

```rust
// crates/nlink/src/netlink/nftables/types.rs:206-216

/// Rule verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
    Jump(String),
    Goto(String),
}
```

Three concrete hazards:

1. **Interior NULs slip through.** A `String` may contain `\0`.
   The chain-name attribute is wire-encoded as a NUL-terminated
   C string (`NFTA_VERDICT_CHAIN` per kernel
   `include/uapi/linux/netfilter/nf_tables.h`). Passing
   `"foo\0bar"` either gets truncated to `"foo"` (silent rename
   from the caller's POV) or is rejected by the kernel with a
   `EINVAL` that says "EINVAL" without explaining why.

2. **Length contract is unenforced.** Kernel
   `NFT_NAME_MAXLEN = 256` (per
   `nft_table_check_unspec_name` in `nft_table.c`). Passing a
   300-byte string passes the `String` constructor and dies at
   apply time with a kernel rejection — late binding for a
   contract that's known statically.

3. **Casing invariants get lost.** Chain identity in the kernel
   is case-sensitive: `Foo` and `foo` are different chains. A
   typed wrapper makes the invariant explicit; the caller's
   intent ("this is a chain ref, not arbitrary user text") is
   visible at the type level.

The 0.19 nftables canonicalization work (Plan 157b, PR #10's
canonical wire form for address / bitwise / NAT) fixed
**wire-format** mismatches. The typed-name pass fixes
**input-side** mismatches.

This finding is **MINOR** in AUDIT_API.md (the kernel
rejects-late, so it's "you'll find out, but later than you
should"). It's worth doing in 0.20 because:

- The change is mechanical.
- `Verdict` is `#[non_exhaustive]` and `Jump(String)` /
  `Goto(String)` are tuple variants — flipping the field type is
  one type-system breaking change, no ripple beyond the few
  construction sites.
- Pairs with Plan 231's accessor-discipline sweep — both move the
  nftables surface closer to the typed-newtype convention.

## 2. The newtype design

```rust
// crates/nlink/src/netlink/nftables/types.rs (or a sibling file)

/// A validated nftables chain name.
///
/// Chain identity in nftables is a `(family, table_name,
/// chain_name)` triple, all case-sensitive. The kernel enforces
/// `NFT_NAME_MAXLEN = 256` (per
/// `include/uapi/linux/netfilter/nf_tables.h`) and rejects
/// interior NULs (the attribute is a NUL-terminated C string at
/// the wire layer).
///
/// Construction validates:
/// - Non-empty.
/// - No interior NUL bytes (`\0`).
/// - At most 255 bytes (one byte reserved for the NUL terminator).
///
/// Round-trip note: `ChainName` is `Display` for natural use in
/// log messages and `AsRef<str>` so it slots into existing
/// `&str`-shaped APIs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainName(String);

impl ChainName {
    /// Maximum chain-name length on the wire, in bytes.
    /// Matches kernel `NFT_NAME_MAXLEN - 1` (the kernel slot is
    /// 256 bytes including the trailing NUL).
    pub const MAX_LEN: usize = 255;

    /// Construct a chain name, validating against the kernel
    /// contract.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.is_empty() {
            return Err(Error::InvalidArgument(
                "ChainName: empty chain names are rejected by nftables".into(),
            ));
        }
        if s.len() > Self::MAX_LEN {
            return Err(Error::InvalidArgument(format!(
                "ChainName: {} bytes exceeds NFT_NAME_MAXLEN-1 ({} bytes)",
                s.len(),
                Self::MAX_LEN,
            )));
        }
        if s.contains('\0') {
            return Err(Error::InvalidArgument(
                "ChainName: interior NUL bytes are rejected — nftables \
                 wire format is a NUL-terminated C string".into(),
            ));
        }
        Ok(Self(s))
    }

    /// Construct without validation — caller asserts the input
    /// was already validated. Useful for parser code that
    /// reconstructs a ChainName from kernel-supplied bytes.
    pub(crate) fn from_validated(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

impl AsRef<str> for ChainName {
    fn as_ref(&self) -> &str { &self.0 }
}

impl fmt::Display for ChainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// Panicking convenience for tests + literal-string call sites
// where the contract is provably upheld. Documented as such.
impl TryFrom<&str> for ChainName {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> { Self::new(s) }
}

impl TryFrom<String> for ChainName {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> { Self::new(s) }
}
```

Deliberate non-impls:

- **No `impl From<&str>` or `From<String>`**. The conversion is
  fallible; `From` is infallible. Using `TryFrom` forces the call
  site to handle the error.
- **No `impl Default`**. There is no sensible "default" chain
  name.
- **`from_validated` is `pub(crate)`**, not `pub`. Parser code
  reconstructing from kernel-supplied bytes can skip the
  validation; external callers cannot.

## 3. The `Verdict` enum changes (breaking)

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
    /// Jump to a named chain (push-and-continue). Validated
    /// against the kernel chain-name contract at construction.
    Jump(ChainName),
    /// Goto a named chain (tail-call). Validated against the
    /// kernel chain-name contract at construction.
    Goto(ChainName),
}
```

The change is a hard compile break for any caller constructing
`Verdict::Jump("foo".to_string())`. The migration is mechanical:

```rust
// Before:
let v = Verdict::Jump("input_filter".to_string());

// After (two equivalent forms):
let v = Verdict::Jump(ChainName::new("input_filter")?);
let v = Verdict::Jump("input_filter".try_into()?);
```

For test code where the chain name is a hard-coded literal that
provably satisfies the contract, the `try_into()` form
short-circuits on the `unwrap()`:

```rust
let v = Verdict::Jump("input_filter".try_into().unwrap());
```

We deliberately do **not** add a `From<&str>` shortcut even for
test code, per Finding A6's lesson about blanket conversions
defeating the typed-newtype.

### 3.1 Adjacent sites — defer or include?

Several adjacent surfaces also take `&str` / `String` for chain
or table names:

- `Chain::new(table: &str, name: &str)` — chain construction
- `Expr::Lookup { set: String, ... }` — set name (similar
  contract, distinct kernel name space)
- `DeclaredChain.name: String` — declarative chain name
- `Table::name` accessor — fetched from the kernel

**Decision for 0.20**: include only `Verdict::{Jump,Goto}`. The
audit explicitly scopes A20 to the `Verdict` variants; the
adjacent sites are flagged for 0.21 alongside a sibling
`TableName` newtype.

**Rationale**: `Chain` and `Table` construction is rarer than
`Verdict::Jump` (one chain instance produces many rules, each
with potentially a jump verdict). The footgun rate is
proportionally higher on `Verdict`. Shipping the smaller surface
in 0.20 also gives us a typed `ChainName` to land in 0.21
without changing its shape — Plan 230 establishes the type,
0.21's follow-on extends its reach.

## 4. Migration

`docs/migration_guide/0.19.0-to-0.20.0.md`:

```markdown
### `Verdict::Jump` / `Verdict::Goto` take typed `ChainName` (Plan 230)

`nftables::Verdict::Jump(String)` and `Verdict::Goto(String)`
now take `ChainName`. The newtype validates non-empty,
no-interior-NUL, and `len() <= NFT_NAME_MAXLEN - 1 = 255` at
construction time — surfacing the kernel's name contract at the
input boundary instead of as a late `EINVAL` at apply time.

Before:
```rust
use nlink::netlink::nftables::Verdict;
let v = Verdict::Jump("input_filter".to_string());
```

After:
```rust
use nlink::netlink::nftables::{Verdict, ChainName};
let v = Verdict::Jump(ChainName::new("input_filter")?);
// or
let v = Verdict::Jump("input_filter".try_into()?);
```

Test code with provably-valid literals can `.unwrap()`:
```rust
let v = Verdict::Jump("input_filter".try_into().unwrap());
```

No `impl From<&str> for ChainName` is provided; the conversion
is fallible by contract, and infallible conversion would defeat
the type's purpose (cf. Finding A6 on `FilterPriority`'s blanket
`From<u16>`).
```

## 5. Test plan

Three test classes:

1. **Constructor contract tests** at the `ChainName` definition
   site, exercising the three rejection conditions:

   ```rust
   #[test]
   fn chainname_rejects_empty() {
       assert!(ChainName::new("").is_err());
   }

   #[test]
   fn chainname_rejects_interior_nul() {
       assert!(ChainName::new("foo\0bar").is_err());
   }

   #[test]
   fn chainname_rejects_overlong() {
       let s = "a".repeat(256);  // 256 bytes > 255 max
       assert!(ChainName::new(s).is_err());
   }

   #[test]
   fn chainname_accepts_max_len() {
       let s = "a".repeat(255);
       assert!(ChainName::new(s).is_ok());
   }
   ```

2. **Round-trip identity tests** building on the Plan 157b chain-
   identity scenarios — applying a config with
   `Verdict::Jump(ChainName::new("foo")?)`, dumping the kernel
   state, parsing back, and confirming the round-trip preserves
   the chain name byte-for-byte. The parser side uses
   `ChainName::from_validated` (no re-validation of kernel
   output).

3. **Apply-side integration test** (root + nft module gated)
   under `crates/nlink/tests/integration/`:

   ```rust
   nlink::require_root!();
   nlink::require_modules!("nf_tables");

   // Build a table + two chains + a rule with Verdict::Jump.
   // Apply atomically; verify via `nft list ruleset` or
   // dump_chain that the jump target resolves correctly.
   ```

## 6. Risks

- **Hard compile break across downstream code**. Anyone with
  `Verdict::Jump("foo".to_string())` in their tree breaks at
  upgrade. Mitigation: the migration is a mechanical
  `s/.to_string())/.try_into()?)/`. The migration guide entry
  in §4 shows both forms. Plus Plan 220's cycle-wide acceptance
  test (a representative downstream consumer upgrading from 0.19
  to 0.20) exercises this path.

- **`try_into()?` requires the caller's function to return
  `Result`**. Tests using `#[test] fn` (no Result return) need
  the `.try_into().unwrap()` form. Document the dual form in
  §4's migration guide entry.

- **Adjacent sites stay un-typed**. `Chain::new(table: &str,
  name: &str)` still takes bare strings after this plan ships.
  That asymmetry will surface — a user wrapping their chain
  name once via `ChainName::new` will then have to `.as_str()`
  it back to pass to `Chain::new`. Documented as a 0.21
  follow-on (cycle seed in INDEX.md at cut time).

- **`from_validated` is a footgun escape hatch**. It's
  `pub(crate)`, but anyone inside the crate can skip validation.
  Audit the call sites; only the parser path should use it. CI
  check: grep `from_validated` in the lib and confirm all hits
  are inside `nftables::parse` or similar.

- **`ChainName::MAX_LEN` is a wire-format constant**. Per the
  0.20 theme ("constants are part of the wire format too") and
  Plan 222's sizeof-constants CI gate, `MAX_LEN` should be
  asserted equal to `NFT_NAME_MAXLEN - 1` from kernel UAPI.
  Plan 222 ingests this constant alongside its XFRM / CT-key
  set.

## 7. Acceptance

This plan ships when:

- ✅ `nftables::ChainName` newtype exists with the §2 contract.
- ✅ `Verdict::Jump(ChainName)` and `Verdict::Goto(ChainName)`
  replace the `String` variants.
- ✅ Constructor contract tests + round-trip identity tests pass.
- ✅ The integration test under
  `crates/nlink/tests/integration/` passes on the privileged CI
  job.
- ✅ Plan 222's CI gate covers `NFT_NAME_MAXLEN`.
- ✅ The migration guide gains the §4 entry.
- ✅ All in-tree callsites migrate to the typed form (no
  `from_validated` outside parser paths).

## 8. Cross-references

- [Plan 220 master](220-0.20-master-plan.md) §3.3 — typed-API
  tightening cluster
- [AUDIT_API.md](../AUDIT_API.md) Finding A20 (this plan's
  source) + Finding A6 (sibling argument against blanket
  conversions)
- [Plan 222 — sizeof CI gate constant-value extension](222-sizeof-gate-constants-plan.md)
  — ingests `NFT_NAME_MAXLEN` alongside this plan's
  `MAX_LEN` constant
- [Plan 231 — message accessor discipline](231-message-accessor-discipline-plan.md)
  — sibling nftables-surface tightening
- 0.19 Plan 157b — chain-identity scenarios this plan's
  round-trip tests build on
- Kernel UAPI:
  `https://raw.githubusercontent.com/torvalds/linux/v6.13/include/uapi/linux/netfilter/nf_tables.h`
  (`NFT_NAME_MAXLEN`, `NFTA_VERDICT_CHAIN`)
- CLAUDE.md `## Type-safe units` — the convention this plan
  extends to nftables chain identifiers
