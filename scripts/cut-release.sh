#!/usr/bin/env bash
# scripts/cut-release.sh — orchestrate an nlink release cut.
#
# Walks the Plan 167 sequence end-to-end with confirmation prompts
# at the irreversible steps. Bakes in the three friction points
# surfaced during the 0.16 cut (Plan 175):
#
#   §3.1  `cargo publish -p nlink --dry-run` fails because the
#         matching `nlink-macros` version isn't on crates.io yet —
#         skip with an explanatory note instead of pretending to
#         validate.
#   §3.2  CHANGELOG `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD`
#         promotion is otherwise manual + easy to forget.
#   §3.3  GitHub release body has a 125000-character limit; the
#         nlink CHANGELOG is bigger. Length-detect + fall back to
#         a "highlights + link to the full file" template.
#
# The script asks for confirmation at every irreversible step
# (publish + merge + tag-push) — pressing Enter advances, anything
# else aborts. Designed for a maintainer working alone; no CI
# automation hooks.
#
# Usage:
#   ./scripts/cut-release.sh 0.17.0
#
# Pre-conditions:
#   - clean working tree
#   - currently on the cycle branch (e.g. `0.17`)
#   - cargo logged in to crates.io (`cargo login`)
#   - gh CLI authenticated (`gh auth status`)
#
# Run from the repo root.

set -euo pipefail

# ---- arg parsing ----

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "usage: $0 <X.Y.Z>" >&2
    exit 2
fi
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: version '$VERSION' is not in X.Y.Z form" >&2
    exit 2
fi

# Cycle branch is the major.minor (`0.17` for `0.17.0`); next cycle
# is `0.<minor+1>` (so cutting 0.17.0 opens 0.18 afterwards).
CYCLE_BRANCH="${VERSION%.*}"
NEXT_MINOR=$((${CYCLE_BRANCH##*.} + 1))
NEXT_CYCLE="${CYCLE_BRANCH%.*}.${NEXT_MINOR}"

# ---- helpers ----

confirm() {
    # Read from /dev/tty so piping doesn't auto-confirm.
    local msg=$1
    printf '\n[CONFIRM] %s — press Enter to continue, anything else to abort: ' "$msg"
    local reply
    read -r reply </dev/tty
    if [[ -n "$reply" ]]; then
        echo "Aborted." >&2
        exit 1
    fi
}

step() {
    echo
    echo "==========================================================================="
    echo "  $1"
    echo "==========================================================================="
}

check_clean_tree() {
    if ! git diff --quiet HEAD || [[ -n "$(git status --porcelain)" ]]; then
        echo "ERROR: working tree is not clean. Commit or stash first." >&2
        git status --short >&2
        exit 1
    fi
}

check_on_release_branch() {
    local current
    current=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$current" != "$CYCLE_BRANCH" ]]; then
        echo "ERROR: expected to be on '$CYCLE_BRANCH' (the $VERSION cycle branch); on '$current'" >&2
        exit 1
    fi
}

check_cargo_metadata_version() {
    # Plan 175 §7: the workspace version is bumped manually mid-
    # cycle; validate the arg matches before we mutate anything.
    local meta_version
    meta_version=$(cargo metadata --no-deps --format-version 1 \
                   | python3 -c 'import json,sys; d=json.load(sys.stdin); [print(p["version"]) for p in d["packages"] if p["name"]=="nlink"]')
    if [[ "$meta_version" != "$VERSION" ]]; then
        echo "ERROR: Cargo.toml says nlink is at $meta_version, but cutting $VERSION." >&2
        echo "       Bump workspace.package.version in the root Cargo.toml first." >&2
        exit 1
    fi
}

check_cargo_login() {
    if [[ ! -f "$HOME/.cargo/credentials.toml" ]] && [[ ! -f "$HOME/.cargo/credentials" ]]; then
        echo "ERROR: not logged in to crates.io. Run 'cargo login' first." >&2
        exit 1
    fi
}

check_gh_auth() {
    if ! gh auth status >/dev/null 2>&1; then
        echo "ERROR: gh CLI not authenticated. Run 'gh auth login' first." >&2
        exit 1
    fi
}

promote_changelog() {
    local date
    date=$(date +%Y-%m-%d)
    # Insert the new version header BELOW the Unreleased line. The
    # Unreleased section stays at the top (empty) for any post-cut
    # hotfix entries; its previous contents move under the new
    # `## [X.Y.Z]` heading.
    if ! grep -q '^## \[Unreleased\]$' CHANGELOG.md; then
        echo "ERROR: CHANGELOG.md missing '## [Unreleased]' line" >&2
        exit 1
    fi
    if grep -q "^## \[$VERSION\]" CHANGELOG.md; then
        echo "ERROR: CHANGELOG.md already has a '## [$VERSION]' section" >&2
        exit 1
    fi
    # Portable sed: write to a tempfile so we don't depend on
    # GNU sed's -i (macOS sed differs).
    awk -v v="$VERSION" -v d="$date" '
        /^## \[Unreleased\]$/ {
            print
            print ""
            print "## [" v "] - " d
            next
        }
        { print }
    ' CHANGELOG.md > CHANGELOG.md.new && mv CHANGELOG.md.new CHANGELOG.md
    echo "CHANGELOG: promoted [Unreleased] → [$VERSION] - $date"
}

push_branch() {
    git push origin "$CYCLE_BRANCH"
}

wait_for_ci_green() {
    local pr_number
    pr_number=$(gh pr list --head "$CYCLE_BRANCH" --json number --jq '.[0].number')
    if [[ -z "$pr_number" ]]; then
        echo "ERROR: no PR open for branch '$CYCLE_BRANCH'. Open one first (draft is fine)." >&2
        exit 1
    fi
    # Status echoes go to stderr so command substitution captures
    # ONLY the bare PR number on stdout. The 0.17 cut surfaced this:
    # without the `>&2` redirect, `PR_NUMBER=$(wait_for_ci_green)`
    # captured the status text plus the gh-checks tabular output
    # into the variable, breaking the subsequent `gh pr merge`.
    echo "Watching CI on PR #$pr_number (Ctrl-C to abort)..." >&2
    # `gh pr checks --watch` polls; both its progress + the final
    # tabular pass/fail report belong on stderr from our caller's
    # perspective. Non-zero exit if any check fails.
    gh pr checks "$pr_number" --watch >&2
    echo "All checks green on PR #$pr_number." >&2
    echo "$pr_number"
}

merge_pr() {
    local pr_number=$1
    # Mark ready if it's a draft; --merge for a merge commit (matches
    # the 0.16 cycle's chosen strategy). Squash/rebase strategies are
    # equally valid — change to --squash/--rebase here if convention
    # shifts.
    gh pr ready "$pr_number" 2>/dev/null || true
    gh pr merge "$pr_number" --merge --subject "$VERSION cycle — release-branch CI green; merging to master for $VERSION cut"
    git checkout master
    git pull --ff-only
}

tag_release() {
    # Repo convention is bare X.Y.Z (no `v` prefix) — matches every
    # tag from 0.1.0 through 0.15.x. v0.16.0 was a one-off outlier.
    git tag -a "$VERSION" -m "nlink $VERSION"
    echo "Tag $VERSION created locally (not yet pushed)."
}

wait_for_macros_indexed() {
    # crates.io index propagation is usually <30s but occasionally
    # slower. Poll `cargo search` (no auth needed) for up to 5 min.
    local deadline=$(( $(date +%s) + 300 ))
    while (( $(date +%s) < deadline )); do
        if cargo search nlink-macros 2>/dev/null \
           | grep -qE "^nlink-macros = \"$VERSION\""; then
            echo "nlink-macros $VERSION indexed on crates.io."
            return 0
        fi
        sleep 10
        echo "  ... still waiting for nlink-macros $VERSION to appear"
    done
    echo "ERROR: timed out waiting for nlink-macros $VERSION on crates.io." >&2
    echo "       Check https://crates.io/crates/nlink-macros manually, then" >&2
    echo "       run 'cargo publish -p nlink' yourself once it's live." >&2
    exit 1
}

extract_changelog_section() {
    # Print the contents of the `## [VERSION]` section, up to (but
    # not including) the next `## [`.
    awk -v v="$VERSION" '
        $0 == "## [" v "]" || $0 ~ "^## \\[" v "\\] " { in_section=1; next }
        in_section && /^## \[/ { exit }
        in_section { print }
    ' CHANGELOG.md
}

build_highlights_body() {
    # Used when the full CHANGELOG section exceeds the GitHub release
    # body limit. The reader gets a concise heading + a link to the
    # full file on the freshly-pushed tag.
    local repo
    repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
    cat <<EOF
# nlink $VERSION

The full CHANGELOG for this release is too long for a GitHub
release body (limit: 125000 chars). Read it at:

https://github.com/$repo/blob/$VERSION/CHANGELOG.md#$(echo "$VERSION" | tr . -)---$(date +%Y-%m-%d)

## Highlights

$(extract_changelog_section | head -80)

...

(See the full CHANGELOG link above for the rest.)
EOF
}

create_github_release() {
    local body
    body=$(extract_changelog_section)
    local max_len=125000
    if [[ ${#body} -gt $max_len ]]; then
        echo "CHANGELOG section is ${#body} chars (> $max_len limit); using highlights body."
        body=$(build_highlights_body)
    fi
    gh release create "$VERSION" \
        --title "nlink $VERSION" \
        --notes "$body" \
        --verify-tag
}

open_next_branch() {
    git checkout -b "$NEXT_CYCLE"
    git push -u origin "$NEXT_CYCLE"
    echo "Next cycle branch '$NEXT_CYCLE' open. Bump workspace version when the first $NEXT_CYCLE-breaking change lands."
}

# ---- main ----

step "Phase 1 — Pre-flight checks"
check_clean_tree
check_on_release_branch
check_cargo_metadata_version
check_cargo_login
check_gh_auth
echo "Pre-flight OK: clean tree, on branch '$CYCLE_BRANCH', Cargo.toml at $VERSION, cargo + gh authenticated."
echo
echo "REMINDER: hardware-only features (XFRM offload / devlink rate /"
echo "          net_shaper) have no CI coverage. Walk the manual"
echo "          checklist before merging this cut:"
echo "          docs/release-validation-manual.md"
confirm "hardware checklist walked (or skipped intentionally)"

step "Phase 2 — CHANGELOG promotion"
promote_changelog
git --no-pager diff CHANGELOG.md
confirm "CHANGELOG promoted; review the diff above"
git add CHANGELOG.md
git commit -m "chore(release): promote [Unreleased] → [$VERSION] - $(date +%Y-%m-%d)"

step "Phase 3 — Push branch and wait for CI"
push_branch
PR_NUMBER=$(wait_for_ci_green)

step "Phase 4 — Publish dry-runs"
echo "Running 'cargo publish -p nlink-macros --dry-run'..."
cargo publish -p nlink-macros --dry-run
echo
echo "NOTE: skipping 'cargo publish -p nlink --dry-run' — known false"
echo "      negative because nlink-macros $VERSION isn't on crates.io"
echo "      yet (Plan 175 §3.1). The real publish below handles the"
echo "      ordering: macros first, wait for index propagation, then nlink."
confirm "dry-run clean — ready to merge to master"

step "Phase 5 — Merge PR to master"
merge_pr "$PR_NUMBER"
echo "Merged PR #$PR_NUMBER; now on master."

step "Phase 6 — Tag locally"
tag_release
confirm "Tag created locally — about to PUBLISH to crates.io (IRREVERSIBLE)"

step "Phase 7 — Publish to crates.io"
echo "Publishing nlink-macros first..."
cargo publish -p nlink-macros
wait_for_macros_indexed
echo "Publishing nlink..."
cargo publish -p nlink

step "Phase 8 — Push tag and create GitHub release"
git push origin "$VERSION"
create_github_release
echo "GitHub release published: https://github.com/$(gh repo view --json nameWithOwner --jq .nameWithOwner)/releases/tag/$VERSION"

step "Phase 9 — Open next cycle branch"
confirm "About to open the next cycle branch '$NEXT_CYCLE' from master"
open_next_branch

echo
echo "==========================================================================="
echo "  Cut complete. $VERSION published; '$NEXT_CYCLE' is the next cycle branch."
echo "==========================================================================="
