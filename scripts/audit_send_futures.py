#!/usr/bin/env python3
"""Every public async fn is checked for a `Send` future (#884).

`#[nlink_macros::send_futures]` on an impl block gives each `pub async fn`
in it a test-only checker that requires its future to be `Send`; on a free
`pub async fn` it gives that one. #879 shipped eight reconcile entry points
whose futures could not be spawned, and no test could have said so, because
none spawned them.

This fails the build on a `pub async fn` with no such attribute: on its impl
block, or on the function itself. A future that is not `Send` on purpose
says why, with `#[send_futures(skip = "reason")]` on the method.

    audit_send_futures.py [ROOT]     audit ROOT (default crates/nlink/src)
    audit_send_futures.py --self-test
"""

import os
import re
import sys
import tempfile

ITEM = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(impl|mod|trait|fn|async fn)\b")
PUB_ASYNC = re.compile(r"^(\s*)pub\s+async\s+fn\s+(\w+)")


def attributes_above(lines, i):
    """The attribute and doc-comment lines directly above line i, multi-line
    attributes included."""
    out = []
    j = i - 1
    while j >= 0:
        stripped = lines[j].strip()
        if stripped.startswith(("#[", "///", "//")):
            out.append(stripped)
            j -= 1
            continue
        if stripped.endswith("]"):
            # The last line of a multi-line attribute: take it from its `#[`.
            k = j
            while k >= 0 and not lines[k].strip().startswith("#["):
                k -= 1
            if k < 0:
                break
            out.extend(line.strip() for line in lines[k : j + 1])
            j = k - 1
            continue
        break
    return out


def checked(attrs):
    """Whether one of the attributes is `#[nlink_macros::send_futures]` or
    `#[send_futures(..)]`. A comment that names it does not count."""
    return any(re.match(r"#\[\s*(nlink_macros\s*::\s*)?send_futures\b", a) for a in attrs)


def audit(root):
    problems = []
    count = 0
    for dirpath, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            lines = open(path, encoding="utf-8").read().split("\n")
            for i, line in enumerate(lines):
                m = PUB_ASYNC.match(line)
                if not m:
                    continue
                count += 1
                indent = len(m.group(1))
                where = f"{path}:{i + 1}: pub async fn {m.group(2)}"
                if checked(attributes_above(lines, i)):
                    continue
                if indent == 0:
                    problems.append(f"{where}: no #[nlink_macros::send_futures]")
                    continue
                # The item it is in: the nearest line above, indented less,
                # that opens an impl, a mod, a trait or a fn.
                owner = None
                for j in range(i - 1, -1, -1):
                    o = ITEM.match(lines[j])
                    if o and len(o.group(1)) < indent:
                        owner = (j, o.group(2))
                        break
                if owner is None or owner[1] in ("mod", "fn", "async fn"):
                    problems.append(f"{where}: no #[nlink_macros::send_futures]")
                elif owner[1] == "trait":
                    continue  # a trait's methods are not `pub async fn`s of nlink's
                elif " for " in lines[owner[0]]:
                    problems.append(f"{where}: in a trait impl, which #[send_futures] cannot check")
                elif not checked(attributes_above(lines, owner[0])):
                    problems.append(
                        f"{where}: its impl block (line {owner[0] + 1}) has no #[nlink_macros::send_futures]"
                    )
    return count, problems


def self_test():
    cases = {
        "covered.rs": ("#[nlink_macros::send_futures]\nimpl A {\n    pub async fn f(&self) {}\n}\n", 0),
        "free.rs": ("/// doc\n#[nlink_macros::send_futures]\npub async fn g() {}\n", 0),
        "skipped.rs": (
            "impl A {\n    #[send_futures(skip = \"holds an Rc\")]\n    pub async fn f(&self) {}\n}\n",
            0,
        ),
        "multiline.rs": (
            "#[cfg_attr(\n    feature = \"x\",\n    derive(Debug)\n)]\n#[nlink_macros::send_futures]\nimpl A {\n"
            "    pub async fn f(&self) {}\n}\n",
            0,
        ),
        "bare_impl.rs": ("impl A {\n    /// doc\n    pub async fn f(&self) {}\n}\n", 1),
        "comment_only.rs": (
            "// not #[nlink_macros::send_futures]\n/// see send_futures\nimpl A {\n    pub async fn f(&self) {}\n}\n",
            1,
        ),
        "other_attr.rs": ("#[derive(send_futures_lookalike)]\npub async fn g() {}\n", 1),
        "bare_free.rs": ("#[tracing::instrument]\npub async fn g() {}\n", 1),
        "in_mod.rs": ("mod m {\n    pub async fn g() {}\n}\n", 1),
        "other_impl.rs": (
            "#[nlink_macros::send_futures]\nimpl A {\n    pub async fn f(&self) {}\n}\n\nimpl B {\n"
            "    pub async fn h(&self) {}\n}\n",
            1,
        ),
    }
    failed = False
    for name, (source, want) in cases.items():
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, name), "w") as f:
                f.write(source)
            _, problems = audit(d)
            if len(problems) != want:
                failed = True
                print(f"self-test FAIL: {name}: {len(problems)} problems, want {want}: {problems}")
    if failed:
        sys.exit(1)
    print(f"OK: the send-futures audit passes and fails where it must ({len(cases)} cases).")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    root = sys.argv[1] if len(sys.argv) > 1 else "crates/nlink/src"
    count, problems = audit(root)
    if problems:
        print(f"FAIL: {len(problems)} public async fns are not checked for a Send future:")
        for p in problems:
            print(f"  {p}")
        print(
            "Put #[nlink_macros::send_futures] on the impl block (or the free function); "
            "a future that is not Send on purpose takes #[send_futures(skip = \"why\")] (#884)."
        )
        sys.exit(1)
    print(f"OK: all {count} public async fns are checked for a Send future.")


if __name__ == "__main__":
    main()
