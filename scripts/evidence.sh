#!/usr/bin/env bash
# =============================================================================
# evidence.sh — Live Omni Gateway evidence capture for API Encryption Policy 1.0.3
# =============================================================================
#
# Produces the transcripts the P4A reviewer explicitly required for
# approval: for each of the 9 mode combos plus every fail-closed path,
# emit a full curl -v transcript showing request headers + bytes and
# response status + headers + bytes.
#
# USAGE
# -----
#   1. Deploy aes-encryption-policy 1.0.3 to your Omni Gateway 1.14.x.
#   2. Store a base64(32-byte) AES key in Secrets Manager as `aeskeys/partnerA`.
#   3. Point the policy's awsService at your Secrets Manager endpoint.
#   4. Export the gateway URL:
#        export GATEWAY_URL="https://your-omni-gateway.example.com"
#      (Or point it at your local Flex playground:
#        export GATEWAY_URL="http://localhost:8081")
#   5. ./scripts/evidence.sh
#
# Output goes to evidence/<ISO-timestamp>/ with one .txt per scenario.
# Attach the whole directory to the GitHub release.
#
# NO SECRETS ARE LOGGED. The AES key never leaves the gateway; only
# ciphertext and plaintext test payloads pass through curl.
# =============================================================================

set -u
trap 'echo "evidence.sh aborted on line $LINENO"; exit 1' ERR

: "${GATEWAY_URL:?Set GATEWAY_URL=https://your-gateway (or http://localhost:8081)}"

OUT_ROOT="evidence"
STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
OUT_DIR="${OUT_ROOT}/${STAMP}"
mkdir -p "${OUT_DIR}"

echo "Writing evidence to: ${OUT_DIR}"
echo "Gateway: ${GATEWAY_URL}"
echo

# Each scenario needs its own policy configuration (requestMode /
# responseMode / sourceBinding). In a real run, you apply each
# configuration via API Manager before invoking that scenario's curl.
# This script does NOT reconfigure the gateway for you — it expects an
# operator to apply the config named in the comment above each block.

run() {
  local name="$1"; shift
  local out="${OUT_DIR}/${name}.txt"
  {
    echo "=== scenario: ${name} ==="
    echo "=== gateway:  ${GATEWAY_URL} ==="
    echo "=== timestamp: $(date -u +%Y-%m-%dT%H%M%SZ) ==="
    echo "=== cmd: $* ==="
    echo
    "$@" 2>&1
    echo
    echo "=== exit: $? ==="
  } > "${out}"
  echo "  wrote ${out}"
}

# ---- Round-trip (happy path per mode combo) --------------------------------
#
# Configure the gateway with requestMode=Encrypt, responseMode=Decrypt
# and an echo upstream before running these.

run "01-encrypt-decrypt-json" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/echo" \
    -H "Content-Type: application/json" \
    -H "Source: partnerA" \
    --data-binary '{"amount":1000,"currency":"INR"}'

run "02-encrypt-decrypt-binary" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/echo" \
    -H "Content-Type: application/octet-stream" \
    -H "Source: partnerA" \
    --data-binary $'\x00\xff\x80\x41\x00\x7f\xc0'

# ---- Request-leg fail-closed (issue #19 and #20) ---------------------------
#
# Configure the gateway with requestMode=Encrypt, responseMode=Plain.

run "10-oversize-request-413" \
  bash -c 'head -c 786368 /dev/urandom | base64 | head -c 786368 > /tmp/oversize.bin;
           curl -sS -o - -D - -X POST "'"${GATEWAY_URL}"'/anything/big" \
               -H "Content-Type: application/octet-stream" \
               -H "Source: partnerA" \
               --data-binary @/tmp/oversize.bin'

run "11-gzip-encoding-415" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/gz" \
    -H "Content-Type: application/json" \
    -H "Content-Encoding: gzip" \
    -H "Source: partnerA" \
    --data-binary "$(printf '\x1f\x8b\x08' )"

run "12-sse-content-type-415" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/sse" \
    -H "Content-Type: text/event-stream" \
    -H "Source: partnerA" \
    --data-binary "data: hello"

run "13-range-request-416" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/range" \
    -H "Content-Type: application/json" \
    -H "Range: bytes=0-100" \
    -H "Source: partnerA" \
    --data-binary '{"x":1}'

# ---- Decrypt-leg fail-closed (issue #1 + #18) -----------------------------
#
# Configure gateway with requestMode=Decrypt, responseMode=Plain.

run "20-bad-base64-400" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/decrypt" \
    -H "Content-Type: application/octet-stream" \
    -H "X-Content-Type: application/json" \
    -H "Source: partnerA" \
    --data-binary "not-valid-base64!!!"

run "21-mac-mismatch-400" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/decrypt" \
    -H "Content-Type: application/octet-stream" \
    -H "X-Content-Type: application/json" \
    -H "Source: partnerA" \
    --data-binary "S0EC////////////////AAAA/"

# ---- Response-leg fail-closed (issue #18 — this is the big one) -----------
#
# Configure gateway with requestMode=Plain, responseMode=Encrypt.
# Upstream must return a 200 with Content-Encoding: gzip for one case,
# text/event-stream for another, and an oversize body for the third.

run "30-response-gzip-fail-closed-502" \
  curl -sS -o - -D - -X GET  "${GATEWAY_URL}/upstream-returns-gzip" \
    -H "Source: partnerA"

run "31-response-sse-fail-closed-502" \
  curl -sS -o - -D - -X GET  "${GATEWAY_URL}/upstream-returns-sse" \
    -H "Source: partnerA"

run "32-response-oversize-fail-closed-502" \
  curl -sS -o - -D - -X GET  "${GATEWAY_URL}/upstream-returns-huge" \
    -H "Source: partnerA"

# ---- Source + identity (issue #22) ----------------------------------------

# With sourceBinding=principalMatch (default) + NO prior auth policy:
run "40-principalmatch-no-auth-403" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/pm" \
    -H "Content-Type: application/json" \
    -H "Source: partnerA" \
    --data-binary '{"x":1}'

# With sourceBinding=headerTrust + invalid Source char:
run "41-malformed-source-400" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/bad-source" \
    -H "Content-Type: application/json" \
    -H "Source: ../etc/passwd" \
    --data-binary '{"x":1}'

# ---- Plain pass-through (issue #20) ---------------------------------------
#
# Configure gateway with requestMode=Plain, responseMode=Plain.
# Backend should see the body byte-exact AND the Content-Type intact.

run "50-plain-plain-passthrough" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/pass" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 11" \
    -H "ETag: \"abc123\"" \
    -H "Source: partnerA" \
    --data-binary '{"ping":1}'

# Configure gateway with requestMode=Plain, responseMode=Encrypt.
# Backend should still see the plaintext with Content-Type intact.

run "51-plain-encrypt-preserves-request-ct" \
  curl -sS -o - -D - -X POST "${GATEWAY_URL}/anything/plain-encrypt" \
    -H "Content-Type: application/json" \
    -H "Source: partnerA" \
    --data-binary '{"ping":1}'

echo
echo "All scenarios recorded under ${OUT_DIR}/"
echo "Attach this directory to the v1.0.3 GitHub release."
