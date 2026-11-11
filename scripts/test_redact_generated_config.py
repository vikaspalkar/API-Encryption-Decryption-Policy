#!/usr/bin/env python3
"""Regression tests for redact_generated_config.py (P4A issue #4).

Every `make build` re-runs the generator, which re-emits the raw-config
leak into src/generated/config.rs. The redact script is responsible for
stripping it. If the generator template ever changes shape, the regex
must either match the new shape or the script must warn loudly — these
tests pin both behaviours.

Run as:
    python3 scripts/test_redact_generated_config.py
Exits non-zero on any failure.
"""
from __future__ import annotations
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from redact_generated_config import redact, REDACTED_MAP_ERR  # noqa: E402


FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    status = "ok" if cond else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        FAILURES.append(name)


# --- Fixture: the shape the generator currently emits -----------------------

ORIGINAL = '''\
use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config { pub foo: String }
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
    abi.setup()?;
    Ok(())
}
'''


def test_redacts_raw_config_leak() -> None:
    print("test_redacts_raw_config_leak")
    out = redact(ORIGINAL)
    check(
        "removes String::from_utf8_lossy(abi.get_configuration()) from init()",
        "String::from_utf8_lossy(abi.get_configuration())" not in out,
    )
    check(
        "removes the original format string",
        "Failed to parse configuration '{}'" not in out,
    )
    check(
        "inserts the redacted map_err",
        REDACTED_MAP_ERR in out,
    )


def test_is_idempotent() -> None:
    print("test_is_idempotent")
    once  = redact(ORIGINAL)
    twice = redact(once)
    check(
        "applying redact twice is identical to once",
        once == twice,
    )


def test_passes_unrelated_code_through_unchanged() -> None:
    print("test_passes_unrelated_code_through_unchanged")
    unrelated = "// nothing to redact here\nfn main() { println!(\"hi\"); }\n"
    check(
        "non-matching input is returned verbatim",
        redact(unrelated) == unrelated,
    )


def test_warns_when_pattern_missing(capfd=None) -> None:
    """The script prints a warning (does NOT raise) if the generator's
    template drifts to a shape we don't recognise. We verify by redirecting
    stderr.
    """
    print("test_warns_when_pattern_missing")
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        out = redact("fn main() {}\n")
    stderr_text = buf.getvalue()
    check(
        "no-match leaves source unchanged",
        out == "fn main() {}\n",
    )
    check(
        "no-match emits a WARN line to stderr",
        "WARN" in stderr_text,
        stderr_text.strip() or "<no stderr>",
    )


def main() -> int:
    test_redacts_raw_config_leak()
    test_is_idempotent()
    test_passes_unrelated_code_through_unchanged()
    test_warns_when_pattern_missing()
    if FAILURES:
        print(f"\nFAILED ({len(FAILURES)}): {FAILURES}")
        return 1
    print("\nAll redactor tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
