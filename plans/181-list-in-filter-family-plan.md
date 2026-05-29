---
to: nlink maintainers
from: nlink-lab upstream-asks report (2026-05-27) §Ask 2 + symmetry sweep
subject: `list_{tables,chains,flowtables,sets}_in(table?, family)` — server-side filter family mirroring `list_rules(table, family)`
status: queued for 0.18 — small additive-only API surface
target version: 0.18.0
parent: (none — single-deliverable plan)
source: nlink-lab maintainer report `nlink-upstream-asks.md` §Ask 2 + adjacent gap on `list_tables` / `list_sets`
created: 2026-05-27
---

# Plan 181 — `list_*_in` filter family

## 1. Why this plan exists

`list_rules(table, family)` already filters server-side via
`NFTA_RULE_TABLE` + `nfgen_family`. Its sibling dump methods
don't:

| Method | Today | Kernel filter available? |
|---|---|---|
| `list_tables()` | family = AF_UNSPEC, no filter | yes — `nfgen_family` |
| `list_chains()` | family = AF_UNSPEC, no `NFTA_CHAIN_TABLE` | yes — both |
| `list_flowtables()` | family = AF_UNSPEC, no `NFTA_FLOWTABLE_TABLE` | yes — both |
| `list_sets(family)` | filters by family but no `NFTA_SET_TABLE` | yes — table too |
| `list_rules(table, family)` | full filter | ✅ already |

The asymmetry is the actual problem — anyone who learns
`list_rules`'s filtering shape assumes the others match, then
gets confused or burns cycles client-side filtering a
multi-table host's dump.

nlink-lab specifically wants this for Plan 158d's per-namespace
nftables snapshot path (ENOBUFS resync over the multicast
events), but the value is general: any controller managing
multiple coexisting tables benefits.

## 2. The change — Option A (new methods, keep originals)

Add five new methods on `Connection<Nftables>`. Don't change
the existing unfiltered methods (no breakage).

```rust
impl Connection<Nftables> {
    pub async fn list_tables_in(&self, family: Family) -> Result<Vec<TableInfo>>;
    pub async fn list_chains_in(&self, table: &str, family: Family) -> Result<Vec<ChainInfo>>;
    pub async fn list_flowtables_in(&self, table: &str, family: Family) -> Result<Vec<Flowtable>>;
    pub async fn list_sets_in(&self, table: &str, family: Family) -> Result<Vec<SetInfo>>;
    // (existing `list_sets(family)` keeps working; the new one
    // adds the table-name filter on top.)
}
```

Naming convention: `_in` reads naturally — "list chains *in*
this table". Matches the established `*_by_name` / `*_by_index`
pattern used elsewhere in the lib for "same operation,
narrower scope".

**Rejected alternative: Option B** (mutate existing signatures
to take `Option<&str>`, `Option<Family>` filters). Pure
breaking change with no semantic win — the caller still has to
spell out `None, None` for "list all". Skip.

## 3. Implementation

Mechanical mirror of `list_rules` (`connection.rs:376-394`).
Per method:

```rust
pub async fn list_chains_in(&self, table: &str, family: Family) -> Result<Vec<ChainInfo>> {
    let mut builder =
        MessageBuilder::new(nft_msg_type(NFT_MSG_GETCHAIN), NLM_F_REQUEST | NLM_F_DUMP);
    let nfgenmsg = NfGenMsg::new(family);
    builder.append(&nfgenmsg);
    builder.append_attr_str(NFTA_CHAIN_TABLE, table);

    let responses = self.nft_dump(builder).await?;
    let mut chains = Vec::new();
    for (family_byte, payload) in &responses {
        let f = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
        if let Some(chain) = parse_chain(payload, f) {
            chains.push(chain);
        }
    }
    Ok(chains)
}
```

| Method | Filter attributes |
|---|---|
| `list_tables_in` | `nfgen_family` only (tables have no parent) |
| `list_chains_in` | `nfgen_family` + `NFTA_CHAIN_TABLE` |
| `list_flowtables_in` | `nfgen_family` + `NFTA_FLOWTABLE_TABLE` |
| `list_sets_in` | `nfgen_family` + `NFTA_SET_TABLE` |

All four use the existing `nft_dump` helper (Plan 172's
timeout-wrapped recv-loop), so no new infrastructure.

Total: ~80 LOC across the four method bodies + their imports.

## 4. Tests

### 4.1 Unit (wire shape)

Per method, build the request, capture the bytes, parse,
assert `nfgen_family` byte and (where applicable) the
`NFTA_*_TABLE` attribute are present. Pattern matches the
existing `add_*_emits_*` tests in the same file.

### 4.2 Integration (root-gated, single test covers all four)

In `crates/nlink/tests/integration/nftables_reconcile.rs` (or
a new `nftables_list.rs` file):

```rust
#[tokio::test]
async fn list_in_filters_match_only_target_table() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables");

    let conn = Connection::<Nftables>::new()?;
    // Build two tables in the same family, each with its own
    // chain/flowtable/set/rule. Use unique nlink-prefixed names
    // so the test cleans up via existing del_table teardown.
    //
    // For each entity, assert:
    //   list_*_in("t1", family).len() == 1  (only t1's entity)
    //   list_*_in("t2", family).len() == 1  (only t2's entity)
    //   list_*().len()                       >= 2  (both visible)
    //
    // Delete both tables on teardown.
    Ok(())
}
```

## 5. Acceptance criteria

- [ ] Four `list_*_in` methods exist on `Connection<Nftables>`
      with rustdoc cross-referencing the unfiltered counterpart.
- [ ] Each method's docstring includes:
      > Server-side filtered via `<attr>` — more efficient than
      > `list_<x>().filter(|x| x.table == "…").collect()` on
      > hosts with many tables.
- [ ] 4 unit tests (one per method) + 1 integration test.
- [ ] CHANGELOG `### Added` block summarizing the surface.
- [ ] One-line note in `docs/migration_guide/0.17.0-to-0.18.0.md`
      under "Added".

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (4 methods × ~20 LOC) | ~45 min |
| Unit tests (4) | ~30 min |
| Integration test (1, multi-entity setup) | ~30 min |
| CHANGELOG + migration guide | ~10 min |
| **Total** | **~2 h** |

## 7. Risks

- **`SetInfo` parse may need a check** — `list_sets(family)`
  already exists, so the parser handles a family-filtered
  dump. Adding `NFTA_SET_TABLE` to the request shouldn't
  surprise the parser (the kernel's response shape doesn't
  change). Worth confirming the integration test covers a
  multi-set scenario to catch any parser drift.

## 8. Out-of-scope follow-ups

- **`list_rules_in_chain(table, chain, family)`** — the
  kernel accepts `NFTA_RULE_CHAIN` as a get-filter too. Not
  currently asked for; defer until a downstream signal.
- **`list_*_streaming`** — the existing
  `dump_stream<T>`/`dump_stream_with_body` infrastructure
  could host streaming variants of these. Same shape as
  Plan 149 closeout work. Defer until a controller needs
  > 100k entities in a single dump.

End of plan.
