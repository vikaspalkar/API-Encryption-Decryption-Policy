#!/usr/bin/env python3
"""Redact the raw-config leak from the generator-emitted config.rs.

P4A issue #4 + #21: `cargo anypoint config-gen` emits an `init()`
function whose default error branch embeds either:
  * `String::from_utf8_lossy(abi.get_configuration())`  — the full
    policy configuration body, which contains `awsAccessSecret`; OR
  * the raw `serde_json::Error`, whose Display includes the offending
    value quoted inline (`invalid type: string "SECRET", expected i64`).

Either leak would surface secret-shaped input in gateway logs. This
script, invoked by `make build-asset-files` immediately after the
generator runs, rewrites that error block to surface only an error
classification + line/column, never the raw body nor the quoted value.

Reviewer #21 required that this script FAIL (exit non-zero) when its
expected pattern no longer matches — a lenient "warn and continue"
let a template drift ship an un-redacted leak. We now:
  * exit 0 if the file is already redacted (idempotent)
  * exit 0 if we matched and rewrote
  * exit 1 if the file still contains a KNOWN-UNSAFE pattern we
    could not rewrite — the build must stop.

Usage:
    python3 -I scripts/redact_generated_config.py src/generated/config.rs
"""
from __future__ import annotations
import pathlib
import re
import sys


# What we rewrite *to*. Value-free, uses classify() + line/column.
REDACTED_MAP_ERR = (
    '.map_err(|err| anyhow::anyhow!('
    '"Failed to parse policy configuration: {} at line {}, column {}", '
    'match err.classify() { '
    'serde_json::error::Category::Io => "I/O", '
    'serde_json::error::Category::Syntax => "malformed JSON", '
    'serde_json::error::Category::Data => "type or structure mismatch", '
    'serde_json::error::Category::Eof => "unexpected end of input" '
    '}, err.line(), err.column()))?;'
)


# The two known-unsafe patterns the generator has historically emitted:
#   1. Raw-config dump via String::from_utf8_lossy(abi.get_configuration())
#   2. Bare `err` interpolation that leaks quoted input values
#
# Each regex is intentionally broad: if the template drifts slightly
# (whitespace, extra parens), we still catch and rewrite. If it drifts
# so far we miss it, main() detects that and fails the build.
UNSAFE_PATTERNS = [
    # 1. Legacy raw-config leak.
    re.compile(
        r"\.map_err\(\|err\|\s*\{\s*"
        r"anyhow::anyhow!\(\s*"
        r'"Failed to parse configuration\s*\'\{\}\'\.\s*Cause:\s*\{\}"\s*,\s*'
        r"String::from_utf8_lossy\(abi\.get_configuration\(\)\)\s*,\s*err\s*"
        r"\)\s*\}\s*\)\?;",
        re.MULTILINE,
    ),
    # 2. Plain `.map_err(|err| anyhow!("…: {}", err))?;` on the config parse.
    #    serde_json::Error's Display quotes the input value — unsafe.
    re.compile(
        r"\.map_err\(\|err\|\s*"
        r"anyhow::anyhow!\(\s*"
        r'"Failed to parse (?:policy )?configuration[^"]*"\s*,\s*err\s*'
        r"\)\s*\)\?;",
        re.MULTILINE,
    ),
]


def redact(src: str) -> tuple[str, bool]:
    """Return (new_source, matched_any). `matched_any` is True if we
    rewrote at least one known-unsafe pattern.
    """
    matched = False
    for pat in UNSAFE_PATTERNS:
        new_src, n = pat.subn(REDACTED_MAP_ERR, src, count=1)
        if n > 0:
            src = new_src
            matched = True
    return src, matched


def is_already_redacted(src: str) -> bool:
    """True when the exact value-free error form is already present
    somewhere in the file (idempotent re-runs)."""
    # Match the key signature: our classify() dispatch inside the anyhow!.
    return (
        "serde_json::error::Category::Syntax" in src
        and "err.classify()" in src
        and "err.line()" in src
    )


def contains_known_leak(src: str) -> bool:
    """Heuristic: after we tried to redact, if the file still contains
    either the raw-config dump or the bare `err` passthrough on a config-
    parse map_err, we have a problem."""
    if "String::from_utf8_lossy(abi.get_configuration())" in src:
        return True
    # Bare `, err)` in a configuration-parse anyhow!: this still leaks the
    # Display of serde_json::Error, which quotes the input.
    bare_err = re.search(
        r'anyhow::anyhow!\(\s*"Failed to parse[^"]*configuration[^"]*"\s*,\s*err\s*\)',
        src,
    )
    return bool(bare_err)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: redact_generated_config.py <path>", file=sys.stderr)
        return 2
    path = pathlib.Path(sys.argv[1])
    src = path.read_text()
    out, matched = redact(src)

    if matched:
        # We rewrote at least one unsafe form; cross-check the result.
        if contains_known_leak(out):
            print(
                "FATAL: redactor rewrote one pattern but another known leak "
                "remains in the output. Refusing to write a partially-safe "
                "file. Inspect " + str(path),
                file=sys.stderr,
            )
            return 1
        path.write_text(out)
        return 0

    # Nothing rewritten: either the file is already redacted (OK) or the
    # generator template has drifted into a shape we don't recognise (NOT
    # OK — a silently-shipping un-redacted leak is what #21 wants to
    # prevent).
    if is_already_redacted(src):
        return 0
    if contains_known_leak(src):
        print(
            "FATAL: redactor did not match any known pattern, but the file "
            "still contains an un-redacted raw-config or serde-error leak. "
            "If `cargo anypoint` changed the generator template, update the "
            "UNSAFE_PATTERNS regex in this script.\n"
            "File: " + str(path),
            file=sys.stderr,
        )
        return 1
    # Unknown template, but no obvious leak either. Still fail so the
    # operator confirms rather than silently ships an unverified file.
    print(
        "FATAL: redactor could neither confirm the file is already redacted "
        "nor find a known pattern to rewrite. Review " + str(path) + " and "
        "either (a) update this script to recognize the new form, or (b) "
        "hand-write the value-free map_err using err.classify() / err.line().",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
