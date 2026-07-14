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

REPO = Path(__file__).resolve().parent.parent
HEADER_DIR = Path("/usr/include/linux")
MAP_FILE = REPO / "scripts" / "audit-uapi-constants.map"
ALLOWLIST_FILE = REPO / "scripts" / "audit-uapi-constants.allowlist"
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

    failures: list[str] = []
    unclassified: list[str] = []
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
                failures.append(
                    f"{path.relative_to(REPO)}: {name}::{variant} = {value}\n"
                    f"    no kernel constant named {kernel_name}\n"
                    f"    (if this variant is nlink-only, map it to `!skip`; if the\n"
                    f"     name just differs, add a `{variant} -> SUFFIX` override)"
                )
                continue

            checked_variants += 1
            expected = kernel[kernel_name]
            if value != expected:
                failures.append(
                    f"{path.relative_to(REPO)}: {name}::{variant} = {value}, "
                    f"but {kernel_name} = {expected}"
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

    print(
        f"OK: {checked_variants} discriminants across {checked_enums} enums match "
        f"{HEADER_DIR} ({len(allowed)} nlink-only enums allowlisted)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
