#!/usr/bin/env python3
"""Diff nlink's hand-transcribed UAPI enums against the kernel headers.

nlink owns its wire format end to end, which means every attribute id, message
type and enum value in the crate was typed in by hand from a kernel header.
That is a transcription task, and transcription drifts: the 0.25.0 cycle found
six independent drifts (#196, #227-#231), all of them silent. Nothing crashed.
`ETHTOOL_A_LINKMODES_OURS` had been split into two variants, so every id after
it was one too high and **link speed simply read as `None` forever**.

This script makes that class mechanically detectable. It:

  1. parses every `enum` in the kernel UAPI headers, evaluating implicit
     increments and constant expressions the way a C compiler would;
  2. parses every `#[repr(uN)] enum` in nlink;
  3. maps each Rust enum to its kernel prefix (scripts/audit-uapi-constants.map)
     and each variant name to its kernel constant name;
  4. reports any variant whose value differs from the kernel's, and any variant
     that does not exist in the kernel at all.

Every `#[repr(uN)]` enum must be *classified*: either mapped to a kernel prefix,
or listed in scripts/audit-uapi-constants.allowlist as nlink-only. An enum that
is neither is an error — a new UAPI enum must not be able to slip in unchecked,
which is the whole point of the gate.
"""

from __future__ import annotations

import glob
import re
import sys
from pathlib import Path

import os

REPO = Path(__file__).resolve().parent.parent
# Overridable so the self-test can point at a trimmed header tree and reproduce
# an older build host — the case that decides whether a missing constant is
# "nlink is newer than you" or "nlink made this up".
HEADER_DIR = Path(os.environ.get("NLINK_UAPI_HEADER_DIR", "/usr/include/linux"))
MAP_FILE = REPO / "scripts" / "audit-uapi-constants.map"
ALLOWLIST_FILE = REPO / "scripts" / "audit-uapi-constants.allowlist"
NEWER_FILE = REPO / "scripts" / "audit-uapi-constants.newer"
CONST_ALLOW_FILE = REPO / "scripts" / "audit-uapi-constants.const-allowlist"
MODMAP_FILE = REPO / "scripts" / "audit-uapi-constants.modmap"
SRC_DIRS = [REPO / "crates" / "nlink" / "src"]


# --------------------------------------------------------------------------
# Kernel headers
# --------------------------------------------------------------------------

# An enum body: everything between `enum [name] {` and the matching `}`.
ENUM_RE = re.compile(r"\benum\s+(\w+)?\s*\{(.*?)\}\s*;", re.S)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def eval_expr(expr: str, consts: dict[str, int]) -> int | None:
    """Evaluate a C enumerator initializer.

    Handles the shapes that actually appear in the UAPI headers: integer and hex
    literals, shifts, bitwise or/and, arithmetic, parentheses, and references to
    constants already defined. Anything else (a sizeof, a cast, a macro we have
    not expanded) returns None and the enumerator is skipped rather than guessed
    at.
    """
    expr = expr.strip()
    if not expr:
        return None
    # Strip C integer-literal suffixes: `0x0080C20001000001ULL` is a perfectly
    # ordinary constant that Python cannot parse. Dropping these silently is not
    # harmless — it is how the MACsec cipher-suite IDs (all `ULL`) stayed
    # invisible to this audit while one of them silently downgraded GCM-AES-256
    # to GCM-AES-128.
    expr = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]+\b", r"\1", expr)
    # Only allow a safe character set through to eval().
    if not re.fullmatch(r"[\w\s()<>|&+\-*/^~]+", expr):
        return None
    # C's `1 << 3` and Python's agree; names resolve from consts.
    #
    # The lookbehind matters: without it the `x` in a hex literal like `0x02`
    # reads as an identifier named `x02`, which resolves to nothing, and every
    # hex-valued constant in the headers is silently dropped.
    names = set(re.findall(r"(?<![\w.])[A-Za-z_]\w*", expr))
    env: dict[str, int] = {}
    for name in names:
        if name not in consts:
            return None
        env[name] = consts[name]
    try:
        value = eval(expr, {"__builtins__": {}}, env)  # noqa: S307
    except Exception:
        return None
    return value if isinstance(value, int) else None


DEFINE_RE = re.compile(r"^\s*#\s*define\s+(\w+)\s+([^\n\\]+)$", re.M)


def parse_kernel_consts() -> dict[str, int]:
    """Every enumerator and integer #define in the UAPI headers, name -> value.

    Both forms matter: attribute ids and message types are `enum`s, but plenty of
    UAPI values nlink mirrors are `#define`s (the bonding modes, for one).
    """
    consts: dict[str, int] = {}
    # Recursive: linux/netfilter/, linux/tc_act/ and friends are where a lot of
    # what nlink mirrors actually lives.
    for header in sorted(glob.glob(str(HEADER_DIR / "**" / "*.h"), recursive=True)):
        try:
            raw = Path(header).read_text(errors="replace")
        except OSError:
            continue
        text = strip_comments(raw)

        # #defines first: enum initializers may reference them.
        for name, expr in DEFINE_RE.findall(text):
            if "(" in name:  # function-like macro
                continue
            value = eval_expr(expr, consts)
            if value is not None:
                consts.setdefault(name, value)

        for _enum_name, body in ENUM_RE.findall(text):
            # if_link.h sprinkles `#define IFLA_COST IFLA_COST` lines *inside*
            # the enum body. Left in, they break the item split and the walk
            # abandons the rest of the enum — which is how IFLA_LINKINFO and
            # everything after it went missing on the first pass.
            body = re.sub(r"^\s*#[^\n]*$", "", body, flags=re.M)
            next_value = 0
            for item in body.split(","):
                item = item.strip()
                if not item:
                    continue
                if "=" in item:
                    name, _, expr = item.partition("=")
                    name = name.strip()
                    value = eval_expr(expr, consts)
                    if value is None:
                        # Unevaluatable initializer: we no longer know where the
                        # implicit sequence is, so abandon the rest of the enum
                        # rather than emit values that are confidently wrong.
                        break
                else:
                    name, value = item, next_value
                if not re.fullmatch(r"\w+", name):
                    break
                consts[name] = value
                next_value = value + 1
    return consts


# --------------------------------------------------------------------------
# nlink enums
# --------------------------------------------------------------------------

RUST_ENUM_RE = re.compile(
    r"#\[repr\(u(?:8|16|32|64)\)\][^{}]*?\benum\s+(\w+)\s*\{(.*?)\n\}",
    re.S,
)
VARIANT_RE = re.compile(r"^\s*(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*,", re.M)


def parse_rust_enums() -> dict[str, tuple[Path, dict[str, int]]]:
    """Every `#[repr(uN)]` enum with explicit discriminants."""
    out: dict[str, tuple[Path, dict[str, int]]] = {}
    for src_dir in SRC_DIRS:
        for path in sorted(src_dir.rglob("*.rs")):
            text = path.read_text()
            # Drop doc comments so `/// FOO = 3` in prose can't be read as code.
            text = re.sub(r"^\s*//[^\n]*$", "", text, flags=re.M)
            for name, body in RUST_ENUM_RE.findall(text):
                variants = {
                    v: int(n, 0) for v, n in VARIANT_RE.findall(body)
                }
                if variants:
                    out[name] = (path, variants)
    return out


# A plain `pub const NAME: uN = <literal>;`. This is how most of the crate's
# wire constants are actually declared — nl80211, devlink, `types/tc.rs`,
# `types/link.rs` and friends — and until #266 none of them were checked at
# all. There are ~3x as many of these as there are enum discriminants.
RUST_CONST_RE = re.compile(
    r"^[ \t]*pub const ([A-Z][A-Z0-9_]*)\s*:\s*u(?:8|16|32|64)\s*="
    r"\s*(0x[0-9a-fA-F_]+|[0-9_]+)\s*;",
    re.M,
)


MOD_RE = re.compile(r"^[ \t]*pub mod (\w+)\s*\{", re.M)


def module_spans(text: str) -> list[tuple[str, int, int]]:
    """`(module_name, body_start, body_end)` for every `pub mod X {` block.

    Brace-counted rather than regexed, so a nested module or a brace inside a
    string does not truncate the span. Used to attribute a constant to the
    module it lives in — the abbreviated modules (`macsec_cipher`, `nha`,
    `seg6_local_flv_op`) name their constants with the kernel *suffix* only,
    so the module is the only place the prefix can come from.
    """
    spans: list[tuple[str, int, int]] = []
    for mo in MOD_RE.finditer(text):
        depth, i = 0, mo.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        spans.append((mo.group(1), mo.end(), i))
    return spans


def parse_modmap() -> dict[str, str]:
    """`rust_module_name -> KERNEL_PREFIX`, for modules whose constants are
    named with the kernel suffix only."""
    if not MODMAP_FILE.exists():
        return {}
    out: dict[str, str] = {}
    for raw in MODMAP_FILE.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        mod, _, prefix = line.partition("=")
        out[mod.strip()] = prefix.strip()
    return out


def parse_rust_consts() -> list[tuple[Path, str, int, "str | None"]]:
    """Every `pub const NAME: uN = <literal>;` in the tree.

    Deliberately *not* name-mangled. The check below only looks at constants
    whose name the kernel also defines, verbatim — which makes it
    zero-false-positive by construction and needs no per-constant mapping.
    Constants nlink names differently from the kernel are simply not covered
    by this pass; they need an enum or a map entry.
    """
    out: list[tuple[Path, str, int, str | None]] = []
    for src_dir in SRC_DIRS:
        for path in sorted(src_dir.rglob("*.rs")):
            text = path.read_text()
            text = re.sub(r"^\s*//[^\n]*$", "", text, flags=re.M)
            spans = module_spans(text)
            for mo in RUST_CONST_RE.finditer(text):
                name = mo.group(1)
                value = int(mo.group(2).replace("_", ""), 0)
                # Innermost enclosing `pub mod`, if any.
                enclosing = None
                best = -1
                for mod_name, start, end in spans:
                    if start <= mo.start() < end and start > best:
                        best, enclosing = start, mod_name
                out.append((path, name, value, enclosing))
    return out


def camel_to_upper_snake(name: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.upper()


# --------------------------------------------------------------------------
# Mapping file
# --------------------------------------------------------------------------


def parse_map() -> dict[str, tuple[str, dict[str, str]]]:
    """RustEnum -> (KERNEL_PREFIX, {RustVariant: KERNEL_SUFFIX_OVERRIDE}).

    Format, one enum per stanza:

        RustEnumName = KERNEL_PREFIX
            RustVariant -> KERNEL_SUFFIX      # when the names don't line up
            RustVariant -> !skip              # nlink-only variant in a UAPI enum
    """
    mapping: dict[str, tuple[str, dict[str, str]]] = {}
    current: str | None = None
    for raw in MAP_FILE.read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw.startswith((" ", "\t")):
            rust, _, prefix = line.partition("=")
            current = rust.strip()
            mapping[current] = (prefix.strip(), {})
        else:
            if current is None:
                raise SystemExit(f"map: override before any enum: {raw!r}")
            variant, _, kernel = line.strip().partition("->")
            mapping[current][1][variant.strip()] = kernel.strip()
    return mapping


def main() -> int:
    if not HEADER_DIR.is_dir():
        print(f"SKIP: {HEADER_DIR} not present (install kernel-headers)")
        return 0

    kernel = parse_kernel_consts()
    if len(kernel) < 1000:
        print(f"FAIL: only parsed {len(kernel)} kernel constants — headers look wrong")
        return 1

    rust = parse_rust_enums()
    mapping = parse_map()
    allowed = {
        line.split("#", 1)[0].strip()
        for line in ALLOWLIST_FILE.read_text().splitlines()
        if line.split("#", 1)[0].strip()
    }

    # Plain `pub const`s that deliberately differ from the kernel symbol of
    # the same name (a mask, a sentinel, an nlink-local alias). Each needs a
    # written reason — the same discipline as the enum allowlist, for the same
    # reason: "it's fine" is what a drifted constant also says.
    const_allowed = {
        line.split("#", 1)[0].strip()
        for line in CONST_ALLOW_FILE.read_text().splitlines()
        if line.split("#", 1)[0].strip()
    } if CONST_ALLOW_FILE.exists() else set()

    # Constants nlink knows about that a given build host's headers may predate.
    # See the file's own header for why this exists and why it is not a hole.
    newer_than_headers = {
        line.split("#", 1)[0].strip()
        for line in NEWER_FILE.read_text().splitlines()
        if line.split("#", 1)[0].strip()
    }

    failures: list[str] = []
    unclassified: list[str] = []
    ahead_of_headers: list[str] = []
    checked_enums = 0
    checked_variants = 0

    for name, (path, variants) in sorted(rust.items()):
        if name in allowed:
            continue
        if name not in mapping:
            unclassified.append(f"  {name}  ({path.relative_to(REPO)})")
            continue

        prefix, overrides = mapping[name]
        checked_enums += 1
        for variant, value in sorted(variants.items(), key=lambda kv: kv[1]):
            override = overrides.get(variant)
            if override == "!skip":
                continue
            suffix = override if override else camel_to_upper_snake(variant)
            kernel_name = f"{prefix}_{suffix}" if suffix else prefix

            if kernel_name not in kernel:
                # nlink deliberately supports kernels newer than its build host,
                # so "this header set has never heard of it" is a legitimate
                # answer — but only for a constant someone has vouched for by
                # name. An unvouched-for missing constant is exactly what an
                # invented variant looks like (#227 shipped two), so it fails.
                if kernel_name in newer_than_headers:
                    ahead_of_headers.append(f"{name}::{variant} ({kernel_name})")
                    continue
                failures.append(
                    f"{path.relative_to(REPO)}: {name}::{variant} = {value}\n"
                    f"    no kernel constant named {kernel_name}\n"
                    f"    Either:\n"
                    f"      - the variant is nlink-only    -> map it to `!skip`\n"
                    f"      - the name just differs        -> add `{variant} -> SUFFIX`\n"
                    f"      - it is newer than these headers -> add {kernel_name}\n"
                    f"        to scripts/audit-uapi-constants.newer, with the kernel\n"
                    f"        version that introduced it"
                )
                continue

            checked_variants += 1
            expected = kernel[kernel_name]
            if value != expected:
                failures.append(
                    f"{path.relative_to(REPO)}: {name}::{variant} = {value}, "
                    f"but {kernel_name} = {expected}"
                )

    # ---- plain `pub const` pass (#266) -------------------------------------
    #
    # Only constants whose name the kernel defines *verbatim* are checked. That
    # is deliberately narrow: it needs no mapping table, cannot mis-mangle a
    # name, and produced zero false positives across the 1573 it matches. A
    # constant nlink spells differently is simply out of scope for this pass —
    # better uncovered than covered by a guess.
    modmap = parse_modmap()
    checked_consts = 0
    for path, name, value, enclosing in parse_rust_consts():
        if name in const_allowed:
            continue
        # A mapped module names its constants with the kernel suffix only, so
        # the full symbol is PREFIX_NAME. Unmapped modules fall back to the
        # exact-name rule.
        prefix = modmap.get(enclosing) if enclosing else None
        kernel_name = f"{prefix}_{name}" if prefix else name
        if kernel_name not in kernel:
            if prefix:
                failures.append(
                    f"{path.relative_to(REPO)}: {enclosing}::{name} = {value}\n"
                    f"    no kernel constant named {kernel_name}\n"
                    f"    (module mapped to {prefix} in "
                    f"scripts/audit-uapi-constants.modmap)"
                )
            continue
        checked_consts += 1
        if value != kernel[kernel_name]:
            where = f"{enclosing}::{name}" if prefix else name
            failures.append(
                f"{path.relative_to(REPO)}: {where} = {value}, "
                f"but {kernel_name} = {kernel[kernel_name]}"
            )

    if unclassified:
        print("FAIL: unclassified #[repr(uN)] enums.\n")
        print("Every one must be either mapped to a kernel prefix in")
        print(f"  {MAP_FILE.relative_to(REPO)}")
        print("or declared nlink-only in")
        print(f"  {ALLOWLIST_FILE.relative_to(REPO)}")
        print("\nA UAPI enum that nobody classified is a UAPI enum nobody is checking.\n")
        print("\n".join(unclassified))
        return 1

    if failures:
        print(f"FAIL: {len(failures)} UAPI constant(s) do not match the kernel.\n")
        for f in failures:
            print(f"  {f}\n")
        print("These are silent-wrong-value bugs: the kernel accepts the message and")
        print("acts on a different attribute than the one you named.")
        return 1

    if ahead_of_headers:
        print(
            f"note: {len(ahead_of_headers)} constant(s) are newer than this host's "
            f"headers and were not checked here:"
        )
        for entry in ahead_of_headers:
            print(f"  {entry}")
        print(
            "      (their values ARE checked on any host whose headers know them — "
            "see scripts/audit-uapi-constants.newer)\n"
        )

    print(
        f"OK: {checked_variants} discriminants across {checked_enums} enums, and "
        f"{checked_consts} plain consts, match {HEADER_DIR} "
        f"({len(allowed)} nlink-only enums, {len(const_allowed)} consts allowlisted)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
