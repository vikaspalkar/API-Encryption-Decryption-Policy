#!/usr/bin/env python3
"""Redact raw-config leak from the generator-emitted src/generated/config.rs.

P4A issue #4: `cargo anypoint config-gen` emits an `init()` function whose
error branch embeds `String::from_utf8_lossy(abi.get_configuration())` — i.e.
the full policy configuration — into its `anyhow!` message. That
configuration contains `awsAccessSecret`, so a parse failure leaks the
credential into gateway logs.

This script, invoked by `make build-asset-files` immediately after the
generator runs, rewrites that error block to surface only the parse cause,
never the raw body.

Usage:
    python3 scripts/redact_generated_config.py src/generated/config.rs
"""
from __future__ import annotations
import pathlib
import re
import sys


REDACTED_MAP_ERR = (
    '.map_err(|err| '
    'anyhow::anyhow!("Failed to parse policy configuration: {}", err))?;'
)


def redact(src: str) -> str:
    # Match the generator's multi-line map_err that contains both the
    # format-string and the lossy UTF-8 call.
    pattern = re.compile(
        r"\.map_err\(\|err\|\s*\{\s*"
        r"anyhow::anyhow!\(\s*"
        r'"Failed to parse configuration\s*\'\{\}\'\.\s*Cause:\s*\{\}"\s*,\s*'
        r"String::from_utf8_lossy\(abi\.get_configuration\(\)\)\s*,\s*err\s*"
        r"\)\s*\}\s*\)\?;",
        re.MULTILINE,
    )
    new_src, n = pattern.subn(REDACTED_MAP_ERR, src, count=1)
    if n != 1:
        print(
            "WARN: redact_generated_config.py did not find the expected "
            "raw-config error pattern in init(). If `cargo anypoint` "
            "changed the generator template, update this script.",
            file=sys.stderr,
        )
    return new_src


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: redact_generated_config.py <path>", file=sys.stderr)
        return 2
    path = pathlib.Path(sys.argv[1])
    src = path.read_text()
    out = redact(src)
    if out != src:
        path.write_text(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
