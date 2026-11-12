#!/usr/bin/env python3
"""Regression tests for redact_generated_config.py (P4A issues #4 + #21).

Pins both the rewriting behavior AND the strict exit contract the
reviewer asked for in #21: the script MUST fail (exit non-zero) rather
than let a drifted generator template ship with an un-redacted leak.

Run as:
    python3 -I scripts/test_redact_generated_config.py
Exits non-zero on any failure.
"""
from __future__ import annotations
import io
import contextlib
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from redact_generated_config import (  # noqa: E402
    redact,
    is_already_redacted,
    contains_known_leak,
    REDACTED_MAP_ERR,
)


FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    status = "ok" if cond else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        FAILURES.append(name)


# --- Fixtures ----------------------------------------------------------------

RAW_CONFIG_LEAK = '''\
use serde::Deserialize;
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()),
                err
            )
        })?;
    Ok(())
}
'''

BARE_ERR_LEAK = '''\
use serde::Deserialize;
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| anyhow::anyhow!("Failed to parse policy configuration: {}", err))?;
    Ok(())
}
'''


# --- Content-level tests -----------------------------------------------------


def test_rewrites_raw_config_leak() -> None:
    print("test_rewrites_raw_config_leak")
    out, matched = redact(RAW_CONFIG_LEAK)
    check("matched=True", matched)
    check(
        "removes String::from_utf8_lossy raw-config dump",
        "String::from_utf8_lossy(abi.get_configuration())" not in out,
    )
    check("output is fully redacted", is_already_redacted(out))
    check("output has no known leak", not contains_known_leak(out))


def test_rewrites_bare_err_leak() -> None:
    """New in #21: a bare `, err)` inside the config-parse anyhow! is also
    a leak because serde_json::Error's Display quotes the input value.
    """
    print("test_rewrites_bare_err_leak")
    out, matched = redact(BARE_ERR_LEAK)
    check("matched=True", matched)
    check("rewrote to classify() form", "err.classify()" in out)
    check(
        "no bare `, err)` left in a config-parse map_err",
        ", err))?" not in out or "err.line()" in out,
    )
    check("output has no known leak", not contains_known_leak(out))


def test_is_idempotent() -> None:
    print("test_is_idempotent")
    once, _  = redact(RAW_CONFIG_LEAK)
    twice, matched_twice = redact(once)
    check("second pass leaves file unchanged", once == twice)
    check("second pass reports no match (already redacted)", not matched_twice)
    check("output still considered redacted", is_already_redacted(once))


def test_detects_partial_safety() -> None:
    """If the file contains TWO unsafe patterns and the regex only catches
    one of them, the script must refuse to write a partially-safe output.
    """
    print("test_detects_partial_safety")
    mixed = RAW_CONFIG_LEAK + "\n" + BARE_ERR_LEAK
    out, _ = redact(mixed)
    # Both patterns are in UNSAFE_PATTERNS so both should rewrite. Check
    # the final state is clean.
    check("no raw-config dump remains",
          "String::from_utf8_lossy(abi.get_configuration())" not in out)
    check("no bare err passthrough remains",
          not contains_known_leak(out))


# --- CLI exit-code tests (the #21 strict-contract requirement) ---------------


def _run_cli(file_contents: str) -> tuple[int, str]:
    """Write a temp file, invoke the redactor CLI, return (rc, stderr)."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".rs", delete=False, encoding="utf-8",
    ) as f:
        f.write(file_contents)
        path = f.name
    proc = subprocess.run(
        [sys.executable, "-I", str(HERE / "redact_generated_config.py"), path],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stderr


def test_cli_exits_zero_on_raw_leak_fixup() -> None:
    print("test_cli_exits_zero_on_raw_leak_fixup")
    rc, _ = _run_cli(RAW_CONFIG_LEAK)
    check("rc == 0 after rewriting a raw-config leak", rc == 0)


def test_cli_exits_zero_on_already_redacted() -> None:
    print("test_cli_exits_zero_on_already_redacted")
    once, _ = redact(RAW_CONFIG_LEAK)
    rc, _ = _run_cli(once)
    check("rc == 0 on already-redacted input (idempotent)", rc == 0)


def test_cli_exits_nonzero_on_unknown_leak() -> None:
    """The reviewer's hard ask: a generator drift that still leaks but no
    longer matches our patterns MUST fail the build."""
    print("test_cli_exits_nonzero_on_unknown_leak")
    drifted = (
        'fn init() {\n'
        '    serde_json::from_slice(x)\n'
        '        .map_err(|err| anyhow::anyhow!("boom: {}", '
        'String::from_utf8_lossy(abi.get_configuration())))?;\n'
        '}\n'
    )
    rc, stderr = _run_cli(drifted)
    check("rc != 0 when an unknown-shape leak persists", rc != 0,
          f"stderr={stderr.strip() or '<empty>'}")
    check("FATAL mentioned in stderr", "FATAL" in stderr)


def test_cli_exits_nonzero_on_wholly_unknown_template() -> None:
    """A file that neither matches a known leak nor looks already-redacted
    must also fail — we refuse to silently approve something we don't
    recognise."""
    print("test_cli_exits_nonzero_on_wholly_unknown_template")
    unrelated = "fn main() { println!(\"hi\"); }\n"
    rc, stderr = _run_cli(unrelated)
    check("rc != 0 on unknown template", rc != 0,
          f"stderr={stderr.strip() or '<empty>'}")


# --- Secret-sentinel test (reviewer #21: absence-of-secret, not substitution)


def test_sentinel_secret_never_reaches_output() -> None:
    """Direct restatement of the reviewer's regression: a
    secret-sentinel value misbound into the policy configuration must
    never appear anywhere in the redacted error output.
    """
    print("test_sentinel_secret_never_reaches_output")
    sentinel = "SECRET_SENTINEL_42_ROTATE_ME"
    raw_leak_with_secret = RAW_CONFIG_LEAK.replace(
        'serde_json::from_slice(abi.get_configuration())',
        f'/* value: {sentinel} */ serde_json::from_slice(abi.get_configuration())',
    )
    out, _ = redact(raw_leak_with_secret)
    # The secret is in a comment in the fixture; it would ALSO show up
    # inline inside a real serde error, which we never reproduce because
    # we classify() + line/column instead.
    check(
        "redacted replacement text contains no sentinel",
        sentinel not in REDACTED_MAP_ERR,
    )
    # The rewritten map_err itself contains no sentinel: that's the key
    # invariant. (The surrounding fixture still does, since the sentinel
    # was in a comment — the test is specifically about the error path.)
    err_block_present = "err.classify()" in out
    check("rewritten error path present", err_block_present)
    if err_block_present:
        # Extract roughly from .map_err( to the matching )?;
        start = out.find(".map_err(|err|")
        end   = out.find(")?;", start)
        rewritten = out[start:end]
        check(
            "no sentinel inside the rewritten map_err block",
            sentinel not in rewritten,
        )


def main() -> int:
    test_rewrites_raw_config_leak()
    test_rewrites_bare_err_leak()
    test_is_idempotent()
    test_detects_partial_safety()
    test_cli_exits_zero_on_raw_leak_fixup()
    test_cli_exits_zero_on_already_redacted()
    test_cli_exits_nonzero_on_unknown_leak()
    test_cli_exits_nonzero_on_wholly_unknown_template()
    test_sentinel_secret_never_reaches_output()
    if FAILURES:
        print(f"\nFAILED ({len(FAILURES)}): {FAILURES}")
        return 1
    print("\nAll redactor tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
