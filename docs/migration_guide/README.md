# nlink migration guides

Per-release upgrade notes for downstream consumers. Each guide
covers the public-API differences between two adjacent releases —
what was deprecated, removed, renamed, or behaviour-changed, plus
the typed replacement to migrate to.

## Convention

One file per upgrade boundary, named `<from>-to-<to>.md`:

```
docs/migration_guide/
├── README.md                  ← this file
├── 0.13.0-to-0.14.0.md        ← upgrading from 0.13.0
└── 0.14.0-to-0.15.0.md        ← upgrading from 0.14.0
```

Files only exist for boundaries that have meaningful migration
work. Pure-additive releases skip a guide and are noted here
instead.

## What each guide covers

In rough order of importance to a downstream maintainer:

1. **Breaking removals** — symbols / modules / methods deleted in
   the new release. Include the typed replacement.
2. **Behaviour changes** — same signature but different runtime
   behaviour (e.g. an error path that used to be silent).
3. **New deprecations** — code that still works but will be
   removed in a future release. Include the planned removal
   release.
4. **Notable additive changes** — new APIs that supersede an
   older pattern but don't force a migration today.
5. **Worked examples** — at least one before/after diff per
   significant change so the migration is mechanical.

Things that **don't** need a migration-guide entry: bug fixes,
documentation updates, internal refactors, new examples /
recipes, performance work, dependency bumps.

## Index

| Boundary | Highlights |
|---|---|
| [`0.13.0-to-0.14.0`](0.13.0-to-0.14.0.md) | Mostly additive: typed-units rollout (25 `parse_params`), reconcile pattern, ctnetlink mutation. **One deprecation**: `nlink::tc::builders::*` and `nlink::tc::options/*` — actual removal shipped in 0.15.0. |
| [`0.14.0-to-0.15.0`](0.14.0-to-0.15.0.md) | **Major release.** The 0.14.0 deprecations are deleted: `tc::builders::*` and `tc::options/*` removed. Typed XFRM SA/SP CRUD, typed standalone-action CRUD. `bins/tc` behaviour changes for unknown kinds and partial-spec `del`. |

## Authoring

When cutting a new release:

1. Read the `[Unreleased]` section of `CHANGELOG.md` since the
   previous release.
2. Create `<previous>-to-<new>.md` from the template-ish shape of
   the existing guides (Removals → Behaviour changes → New
   deprecations → Notable additive → Worked examples).
3. Add a row to the index table above.
4. Cross-link from the release's CHANGELOG entry.

The CHANGELOG is the source of truth for *what* changed; the
migration guide is the source of truth for *how to upgrade*.
Don't duplicate; link.
