#!/usr/bin/env bash
# #304 — no ```ignore doc examples.
#
# `ignore` tells rustdoc to render the block and never compile it. 508 of
# them had accumulated, and once nothing compiles an example it rots
# silently against every rename, signature change and typed-unit migration.
# The 0.26 conversion found the damage: examples calling `add_qdisc` with
# three arguments, passing "100mbit" where `Rate` is expected, importing
# `nlink::netlink::protocol::Route` (a private module) and
# `rip_tuntap::{TunTap, Mode}` (a crate name three releases stale). It also
# found five *library* bugs the examples had been documenting around —
# #310, #313, #315, #316, #317.
#
# So the rule is: a doc example compiles. `no_run` when it needs a kernel,
# which is nearly always; plain when it can actually run.
#
# `text` is the escape hatch, for a block that is not Rust — a wire-format
# sketch, a tc(8) command line, an illustration of a private helper a
# doctest cannot call. `compile_fail` and `should_panic` are fine: rustdoc
# compiles both.
#
# Scope is every doc comment the crate ships — `src/`, the examples, the
# proc-macro crate and the bins — plus `docs/recipes/`, whose markdown is
# compiled as doctests through `src/recipe_doctests.rs` (#319). An example's
# module docs are documentation like any other; one `ignore` had already
# slipped through by living in `examples/` rather than `src/`.
#
# What counts as a hit: ```ignore, and ```rust,ignore in any attribute order.

set -euo pipefail

hits=$(grep -rnE '^\s*(///|//!)?\s*```[a-z_,]*\bignore\b' \
    crates/nlink/src crates/nlink/examples crates/nlink-macros bins \
    docs/recipes --include='*.rs' --include='*.md' 2>/dev/null || true)

if [ -n "$hits" ]; then
    echo "audit-doc-examples: \`\`\`ignore doc example(s) found."
    echo
    echo "$hits"
    echo
    echo "An \`ignore\` block is never compiled, so it rots silently against"
    echo "renames and signature changes — that is how 508 of them ended up"
    echo "documenting an API that no longer existed (#304)."
    echo
    echo "Use \`no_run\` (compiles, does not run) for anything needing a"
    echo "kernel, or \`text\` for a block that is not Rust at all."
    exit 1
fi

echo "audit-doc-examples: every doc example compiles (no \`\`\`ignore)."
