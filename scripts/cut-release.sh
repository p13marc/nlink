#!/usr/bin/env bash
# scripts/cut-release.sh — cut an nlink release on this Forgejo forge.
#
# The sequence the 0.27.0–0.29.0 cuts followed by hand, with a
# confirmation at every irreversible step:
#
#   1. Pre-flight: tools, `fj` signed in, clean tree, master == origin/master,
#      workspace version == X.Y.Z, no tag yet, a non-empty [Unreleased], the
#      migration guide for a minor release, README in sync.
#   2. Release branch `release/X.Y.Z` with one commit `X.Y.Z`: CHANGELOG
#      [Unreleased] promoted to [X.Y.Z] - date (a fresh empty [Unreleased]
#      above it), plus whatever you edit while the script waits (the
#      CLAUDE.md "Active work" narrative).
#   3. `cargo publish -p nlink-macros --dry-run`. Not nlink's: it resolves
#      nlink-macros X.Y.Z on crates.io, which is not there yet (Plan 175).
#   4. Push, open the PR "release: X.Y.Z", wait for every check to pass.
#   5. Merge it — then CHECK master has the release commit. On 2026-10-07
#      Forgejo printed "Merged" for three PRs that never reached master.
#   6. IRREVERSIBLE: tag X.Y.Z (bare semver; a `v` tag does not fire
#      release.yml, #249) on the merge commit and push it. release.yml
#      creates the Forgejo release and attaches the tarball + SHA256SUMS.
#   7. IRREVERSIBLE: dispatch publish-crates.yml on the tag. It runs the
#      semver gate, then publishes nlink-macros, then nlink. It runs on the
#      `ubuntu-24.04` lane, which can sit Pending for hours: the script
#      waits for crates.io rather than reading a slow lane as a failure.
#   8. What is left by hand: the GitHub mirror's release, deleting a
#      per-cycle `plans/` directory, and anything the run printed.
#
# Usage:
#   scripts/cut-release.sh X.Y.Z [--dry-run] [--from N]
#
#   --dry-run  Run the read-only checks, show the CHANGELOG promotion as a
#              diff, and print every command that would change something —
#              without running any of them. Check failures are reported,
#              not fatal.
#   --from N   Resume at phase N (2-7) after an interruption — e.g. a CI
#              wait you cut short. Phases before N are assumed done.
#
# Pre-conditions: run from the repo root, on master, with `fj` signed in
# (`fj whoami`). Publishing itself happens in CI with the repository's
# CARGO_REGISTRY_TOKEN, so no local `cargo login` is needed.

set -euo pipefail

VERSION=""
DRY_RUN=0
FROM=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --from) FROM="${2:?--from needs a phase number}"; shift ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) VERSION="$1" ;;
    esac
    shift
done
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: $0 <X.Y.Z> [--dry-run] [--from N]" >&2
    exit 2
fi
PATCH="${VERSION##*.}"
BRANCH="release/$VERSION"
TITLE="release: $VERSION"
CI_TIMEOUT_SECS="${CI_TIMEOUT_SECS:-14400}"       # 4 h: a lane can sit Pending
PUBLISH_TIMEOUT_SECS="${PUBLISH_TIMEOUT_SECS:-21600}"
FAILED_CHECKS=0

# ---- helpers ----

step() {
    echo
    echo "==========================================================================="
    echo "  $1"
    echo "==========================================================================="
}

fail() {
    echo "ERROR: $*" >&2
    if (( DRY_RUN )); then
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        exit 1
    fi
}

# Run a command that changes something; in --dry-run, only print it.
run() {
    if (( DRY_RUN )); then
        printf '  [dry-run] would run:'
        printf ' %q' "$@"
        echo
    else
        "$@"
    fi
}

confirm() {
    local msg=$1
    if (( DRY_RUN )); then
        echo "  [dry-run] would ask: $msg"
        return
    fi
    # Read from /dev/tty so piping doesn't auto-confirm.
    printf '\n[CONFIRM] %s — press Enter to continue, anything else to abort: ' "$msg"
    local reply
    read -r reply </dev/tty
    if [[ -n "$reply" ]]; then
        echo "Aborted." >&2
        exit 1
    fi
}

phase() { (( $1 >= FROM )); }

# fj decorates its output with Unicode isolates (U+2068/U+2069) and style
# markers, even in a pipe; strip them so it can be grepped.
fj_plain() {
    fj --style minimal "$@" 2>&1 | sed -e 's/\xe2\x81\xa8//g' -e 's/\xe2\x81\xa9//g' -e 's/STYLE()//g'
}

previous_release() {
    git tag --list '[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname \
        | grep -vx "$VERSION" | head -1
}

# The open PR for the release branch, by its title.
release_pr_number() {
    fj_plain pr search "$TITLE" | grep -oE '#[0-9]+' | head -1 | tr -d '#'
}

# ---- phase 1: pre-flight ----

preflight() {
    step "Phase 1 — Pre-flight checks"
    local tool
    for tool in git cargo fj python3; do
        command -v "$tool" >/dev/null || fail "'$tool' is not installed"
    done
    fj_plain whoami | grep -q "signed into" || fail "fj is not signed in (run 'fj auth login')"

    if ! git diff --quiet HEAD || [[ -n "$(git status --porcelain)" ]]; then
        fail "working tree is not clean"
    fi
    git fetch -q origin
    local current
    current=$(git rev-parse --abbrev-ref HEAD)
    [[ "$current" == master ]] || fail "on '$current'; a cut starts from master"
    [[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/master)" ]] \
        || fail "local master is not origin/master (pull first)"

    local meta_version
    meta_version=$(cargo metadata --no-deps --format-version 1 \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(p["version"] for p in d["packages"] if p["name"]=="nlink"))')
    [[ "$meta_version" == "$VERSION" ]] \
        || fail "the workspace says nlink $meta_version, not $VERSION (bump both pins in the root Cargo.toml)"

    if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null \
        || git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1; then
        fail "tag $VERSION already exists"
    fi

    grep -q '^## \[Unreleased\]$' CHANGELOG.md || fail "CHANGELOG.md has no '## [Unreleased]' line"
    ! grep -q "^## \[$VERSION\]" CHANGELOG.md || fail "CHANGELOG.md already has '## [$VERSION]'"
    local unreleased_lines
    unreleased_lines=$(awk '/^## \[Unreleased\]$/{f=1; next} f && /^## \[/{exit} f && NF' CHANGELOG.md | wc -l)
    (( unreleased_lines > 0 )) || fail "CHANGELOG.md's [Unreleased] section is empty"

    local prev
    prev=$(previous_release)
    if [[ "$PATCH" == 0 && -n "$prev" ]]; then
        local guide="docs/migration_guide/${prev}-to-${VERSION}.md"
        [[ -f "$guide" ]] || fail "no migration guide at $guide (every minor release gets one)"
        grep -q "${prev}-to-${VERSION}.md" docs/migration_guide/README.md \
            || fail "docs/migration_guide/README.md does not list $guide"
    fi
    if [[ -x scripts/check-readme.sh ]]; then
        scripts/check-readme.sh >/dev/null || fail "scripts/check-readme.sh failed"
    fi

    echo "Pre-flight: cutting $VERSION (previous release ${prev:-none})."
    echo
    echo "REMINDER: hardware-only features (XFRM offload, devlink rate,"
    echo "          net_shaper) have no CI coverage. Walk the manual checklist"
    echo "          in docs/release-validation-manual.md before merging this cut."
    confirm "hardware checklist walked (or skipped on purpose)"
}

# ---- phase 2: release branch + commit ----

promote_changelog() {
    # The [Unreleased] contents move under `## [X.Y.Z] - date`; an empty
    # [Unreleased] stays on top for the next cycle.
    local out=$1
    awk -v v="$VERSION" -v d="$(date +%Y-%m-%d)" '
        /^## \[Unreleased\]$/ { print; print ""; print "## [" v "] - " d; next }
        { print }
    ' CHANGELOG.md > "$out"
}

release_commit() {
    step "Phase 2 — Release branch and the $VERSION commit"
    local promoted
    promoted=$(mktemp)
    promote_changelog "$promoted"
    diff -u CHANGELOG.md "$promoted" | head -20 || true
    if (( DRY_RUN )); then
        rm -f "$promoted"
        run git switch -c "$BRANCH"
        echo "  [dry-run] would write the promoted CHANGELOG.md shown above"
        run git commit -am "$VERSION"
        return
    fi
    git switch -c "$BRANCH"
    mv "$promoted" CHANGELOG.md
    echo
    echo "Now update CLAUDE.md's 'Active work' (this cycle shipped, its lessons)"
    echo "and anything else that belongs in the release commit. Leave the"
    echo "edits in the working tree; the script commits them with CHANGELOG.md."
    confirm "release edits done"
    git --no-pager diff --stat
    confirm "commit these as '$VERSION'"
    git commit -qam "$VERSION"
}

# ---- phase 3: publish dry-run ----

publish_dry_run() {
    step "Phase 3 — Publish dry-run"
    run cargo publish -p nlink-macros --dry-run
    echo "Skipping 'cargo publish -p nlink --dry-run': it resolves nlink-macros"
    echo "$VERSION on crates.io, which is only there after the real publish."
}

# ---- phase 4: PR + CI ----

open_pr_and_wait() {
    step "Phase 4 — Push, open the PR, wait for CI"
    run git push -u origin "$BRANCH"
    if (( DRY_RUN )); then
        run fj pr create --base master --head "$BRANCH" --body "Release $VERSION." "$TITLE"
        echo "  [dry-run] would poll 'fj pr status <n>' until every check passes"
        return
    fi
    local pr
    pr=$(release_pr_number || true)
    if [[ -z "$pr" ]]; then
        fj pr create --base master --head "$BRANCH" \
            --body "Release $VERSION: the CHANGELOG promoted to [$VERSION]. See CHANGELOG.md and docs/migration_guide/." \
            "$TITLE"
        pr=$(release_pr_number)
    fi
    echo "PR #$pr. Waiting for CI (up to $((CI_TIMEOUT_SECS / 3600)) h; Ctrl-C and --from 4 to resume)."
    local deadline=$(( $(date +%s) + CI_TIMEOUT_SECS ))
    while :; do
        local status
        status=$(fj_plain pr status "$pr")
        if grep -qE '(Failure|Error|Cancel)' <<<"$status"; then
            echo "$status" >&2
            fail "a check failed on PR #$pr"
        fi
        if grep -q ' — ' <<<"$status" && ! grep -qE '^- .*(Pending|Running|Waiting)' <<<"$status" \
            && grep -qE '^- .*Success' <<<"$status"; then
            echo "$status"
            break
        fi
        (( $(date +%s) < deadline )) || fail "CI still not green on PR #$pr; resume with --from 4"
        echo "  $(grep -cE '^- .*(Pending|Running|Waiting)' <<<"$status") check(s) pending..."
        sleep 60
    done
}

# ---- phase 5: merge + verify ----

merge_and_verify() {
    step "Phase 5 — Merge to master, and check it really merged"
    local pr release_sha
    release_sha=$(git rev-parse --verify -q "$BRANCH" || echo "<release commit>")
    pr=$( (( DRY_RUN )) && echo "<n>" || release_pr_number )
    confirm "merge PR #$pr into master"
    run fj pr merge "$pr" -M merge -d
    if (( DRY_RUN )); then
        echo "  [dry-run] would check that $release_sha is an ancestor of origin/master"
        return
    fi
    local i
    for i in 1 2 3 4 5 6; do
        git fetch -q origin
        if git merge-base --is-ancestor "$release_sha" origin/master; then
            echo "master has the release commit $release_sha."
            git switch -q master
            git merge -q --ff-only origin/master
            return
        fi
        sleep 10
    done
    fail "Forgejo said merged, but origin/master does not contain $release_sha. Re-open the PR from $BRANCH and merge again (see the forgejo-pr-workflow note)."
}

# ---- phase 6: tag ----

tag_release() {
    step "Phase 6 — Tag $VERSION (IRREVERSIBLE)"
    local target
    target=$( (( DRY_RUN )) && echo "origin/master" || git rev-parse origin/master )
    confirm "tag $target as $VERSION and push the tag — this fires release.yml"
    run git tag -a "$VERSION" -m "nlink $VERSION" "$target"
    run git push origin "refs/tags/$VERSION"
    echo "release.yml creates the Forgejo release with the tarball and SHA256SUMS."
}

# ---- phase 7: publish ----

publish() {
    step "Phase 7 — Publish to crates.io (IRREVERSIBLE)"
    local breaking=no
    # In 0.x, a minor release is the breaking one (the semver-checks
    # convention: the first breaking PR of a cycle bumps the minor).
    [[ "$PATCH" == 0 ]] && breaking=yes
    confirm "dispatch publish-crates.yml on $VERSION (allow_breaking=$breaking) — publishes nlink-macros, then nlink"
    run fj actions dispatch publish-crates.yml "$VERSION" -I "allow_breaking=$breaking"
    if (( DRY_RUN )); then
        echo "  [dry-run] would wait for nlink $VERSION on crates.io"
        return
    fi
    echo "Dispatched. If fj refuses the inputs, dispatch 'Publish crates' from the"
    echo "Actions tab on tag $VERSION with allow_breaking=$breaking instead."
    echo "Waiting for crates.io (the ubuntu-24.04 lane can sit Pending for hours)."
    local deadline=$(( $(date +%s) + PUBLISH_TIMEOUT_SECS ))
    until cargo search nlink --limit 1 2>/dev/null | grep -qE "^nlink = \"$VERSION\""; do
        (( $(date +%s) < deadline )) || fail "nlink $VERSION not on crates.io yet; check 'fj actions tasks'"
        sleep 120
        fj_plain actions tasks | grep -i "publish" | head -2 | sed 's/^/  /' || true
    done
    echo "nlink $VERSION is on crates.io."
}

# ---- main ----

phase 1 && preflight
phase 2 && release_commit
phase 3 && publish_dry_run
phase 4 && open_pr_and_wait
phase 5 && merge_and_verify
phase 6 && tag_release
phase 7 && publish

step "Done"
if (( DRY_RUN )); then
    echo "Dry run: $FAILED_CHECKS check(s) failed; nothing was changed."
    (( FAILED_CHECKS == 0 )) || exit 1
    exit 0
fi
cat <<EOF
$VERSION is tagged and published. Left by hand:
  - the GitHub mirror's release (gh is not used from here);
  - deleting a per-cycle plans/ directory, if the cycle had one;
  - the next cycle stays on master; bump the workspace version with its
    first breaking PR.
EOF
