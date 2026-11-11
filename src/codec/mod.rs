//! AES-256-CBC-HMAC codec (wire format **v2**).
//!
//! Issue #1 — v1 used base64(IV ‖ ciphertext) with **no authentication**.
//! That shape is malleable: an attacker who can resubmit altered
//! ciphertext can flip plaintext bits in the first block without knowing
//! the key. v2 fixes this by adding Encrypt-then-MAC:
//!
//! ```text
//!   wire = base64(
//!     magic (2)  = 0x4B 0x41    // "KA"
//!     version(1) = 0x02
//!     iv (16)    = CSPRNG
//!     ciphertext (n blocks of 16 bytes each, PKCS#7 padded)
//!     mac (32)   = HMAC-SHA256(mac_key, magic ‖ version ‖ iv ‖ ciphertext)
//!   )
//! ```
//!
//! The MAC covers every byte before it, including the version byte, so
//! an attacker cannot downgrade a v2 envelope to v1. The MAC key is
//! derived from the AES key via HKDF-SHA256 with a per-use label so the
//! operator still manages a single 32-byte secret.
//!
//! v1 envelopes are **rejected** — this is the hard cut documented in
//! the migration guide. If v1 interop is ever needed, add a second path
//! gated behind a config flag.
//!
//! Byte-oriented (issue #9) — inputs and outputs are `&[u8]` / `Vec<u8>`
//! so arbitrary binary bodies round-trip exactly.

use std::fmt;

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use block_modes::{BlockMode, Cbc};
use block_padding::Pkcs7;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::support::TraceCtx;
use crate::support::log::{emit as trace, Level};

type Cbc256 = Cbc<Aes256, Pkcs7>;
type HmacSha256 = Hmac<Sha256>;

const KEY_BYTES: usize = 32;
const IV_BYTES: usize = 16;
const MAC_BYTES: usize = 32;
const MAGIC: [u8; 2] = [0x4B, 0x41]; // "KA"
const VERSION_V2: u8 = 0x02;
const HEADER_BYTES: usize = MAGIC.len() + 1 /* version */ + IV_BYTES;
/// Minimum raw-envelope size: header + one ciphertext block + MAC.
const MIN_ENVELOPE_BYTES: usize = HEADER_BYTES + 16 + MAC_BYTES;

/// Label for the HKDF step that derives the MAC key from the AES key.
/// Changing this label breaks compatibility with existing envelopes, so
/// it must stay identical across the server and every client.
const MAC_KEY_LABEL: &[u8] = b"api-encryption-decryption-policy/v2/mac-key";

#[derive(Debug)]
pub enum CodecError {
    /// Base64-decoded key was not 32 bytes long.
    KeyLength,
    /// Host failed to produce random bytes for the IV. Fail closed; never
    /// substitute a fixed IV.
    EntropyFailed(String),
    /// Ciphertext wrapper was not valid base64 or was below the minimum
    /// envelope size.
    BadBase64,
    /// Envelope magic bytes didn't match — not a v2 envelope at all.
    BadMagic,
    /// Envelope version byte is not 0x02. v1 envelopes land here.
    UnsupportedVersion(u8),
    /// MAC tag did not match the derived key. Either the envelope was
    /// tampered with, the wrong AES key is being used, or the MAC key
    /// derivation label disagrees between sender and receiver.
    MacMismatch,
    /// Underlying block-mode library rejected the key/IV pair.
    CipherInit(String),
    /// Padding was incorrect — only reachable when MAC passes but the
    /// AES block/padding is malformed (a well-formed v2 envelope with
    /// corrupted ciphertext should fail MAC first).
    Decrypt(String),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyLength             => f.write_str("Missing or Invalid AES Key"),
            Self::EntropyFailed(e)      => write!(f, "IV entropy generation failed: {e}"),
            Self::BadBase64             => f.write_str("Base64 decoding failed or envelope too short"),
            Self::BadMagic              => f.write_str("Envelope does not start with v2 magic bytes"),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported envelope version 0x{v:02x} (only v2 is accepted)"),
            Self::MacMismatch           => f.write_str("MAC verification failed — envelope is tampered or keys disagree"),
            Self::CipherInit(e)         => write!(f, "Cipher creation failed: {e}"),
            Self::Decrypt(e)            => write!(f, "AES decryption failed: {e}"),
        }
    }
}
impl std::error::Error for CodecError {}

/// A codec bound to a specific AES-256 key. At construction we derive the
/// MAC key once via HKDF; the derivation is cheap but it's still a single
/// hash chain we don't want to repeat per request.
pub struct Codec {
    enc_key: Vec<u8>,
    mac_key: [u8; 32],
}

impl Codec {
    /// Decode a base64-encoded 32-byte key and build a codec from it.
    pub fn from_b64_key(b64_key: &str) -> Result<Self, CodecError> {
        let enc_key = B64.decode(b64_key).unwrap_or_default();
        if enc_key.len() != KEY_BYTES {
            return Err(CodecError::KeyLength);
        }

        // HKDF with no salt, labelled info. One-call extract-and-expand.
        let hk = Hkdf::<Sha256>::new(None, &enc_key);
        let mut mac_key = [0u8; 32];
        hk.expand(MAC_KEY_LABEL, &mut mac_key)
            .expect("HKDF expand to 32 bytes is infallible with SHA-256");

        Ok(Self { enc_key, mac_key })
    }

    fn cipher(&self, iv: &[u8]) -> Result<Cbc256, CodecError> {
        Cbc256::new_from_slices(&self.enc_key, iv)
            .map_err(|e| CodecError::CipherInit(e.to_string()))
    }

    fn mac(&self, data: &[u8]) -> [u8; MAC_BYTES] {
        let mut m = <HmacSha256 as Mac>::new_from_slice(&self.mac_key)
            .expect("HMAC accepts any key length");
        m.update(data);
        let tag = m.finalize().into_bytes();
        let mut out = [0u8; MAC_BYTES];
        out.copy_from_slice(&tag);
        out
    }

    /// Encrypt arbitrary plaintext bytes and return a v2 base64 envelope.
    pub fn seal(&self, plaintext: &[u8], ctx: &TraceCtx<'_>) -> Result<Vec<u8>, CodecError> {
        let mut iv = [0u8; IV_BYTES];
        if let Err(e) = getrandom::getrandom(&mut iv) {
            trace(ctx, Level::Error, &format!("Encrypt Payload - IV entropy failed: {e}"));
            return Err(CodecError::EntropyFailed(e.to_string()));
        }

        let cipher = self.cipher(&iv).map_err(|e| {
            trace(ctx, Level::Error, &format!("Encrypt Payload - Cipher creation failed: {e}"));
            e
        })?;
        let ciphertext = cipher.encrypt_vec(plaintext);

        // Assemble the pre-MAC prefix: magic ‖ version ‖ iv ‖ ciphertext
        let mut buf = Vec::with_capacity(HEADER_BYTES + ciphertext.len() + MAC_BYTES);
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION_V2);
        buf.extend_from_slice(&iv);
        buf.extend_from_slice(&ciphertext);

        // Compute MAC over everything so far, append it.
        let tag = self.mac(&buf);
        buf.extend_from_slice(&tag);

        Ok(B64.encode(buf).into_bytes())
    }

    /// Verify + decrypt a v2 envelope, returning raw plaintext bytes.
    pub fn open(&self, b64_blob: &[u8], ctx: &TraceCtx<'_>) -> Result<Vec<u8>, CodecError> {
        // Strip ASCII whitespace at the byte level — intermediaries
        // sometimes line-wrap base64.
        let cleaned: Vec<u8> = b64_blob
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();

        let framed = B64.decode(&cleaned).map_err(|_| {
            trace(ctx, Level::Error, "Decrypt Payload - Base64 decoding failed");
            CodecError::BadBase64
        })?;

        if framed.len() < MIN_ENVELOPE_BYTES {
            return Err(CodecError::BadBase64);
        }

        // Validate magic + version BEFORE touching the MAC.
        if framed[0..2] != MAGIC {
            trace(ctx, Level::Error, "Decrypt Payload - Bad magic bytes (not a v2 envelope)");
            return Err(CodecError::BadMagic);
        }
        if framed[2] != VERSION_V2 {
            trace(ctx, Level::Error, &format!(
                "Decrypt Payload - Unsupported version 0x{:02x}", framed[2]
            ));
            return Err(CodecError::UnsupportedVersion(framed[2]));
        }

        // Split into (data | mac).
        let mac_start = framed.len() - MAC_BYTES;
        let (data, tag) = framed.split_at(mac_start);

        // Constant-time MAC check — ALWAYS before any crypto use of the
        // ciphertext, to deny padding oracles on malformed ciphertext.
        let expected = self.mac(data);
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            trace(ctx, Level::Error, "Decrypt Payload - MAC verification failed");
            return Err(CodecError::MacMismatch);
        }

        // MAC verified — safe to decrypt.
        let iv = &data[3..3 + IV_BYTES];
        let ciphertext = &data[HEADER_BYTES..];
        let cipher = self.cipher(iv).map_err(|e| {
            trace(ctx, Level::Error, &format!("Decrypt Payload - Cipher creation failed: {e}"));
            e
        })?;
        cipher.decrypt_vec(ciphertext).map_err(|e| {
            trace(ctx, Level::Error, &format!("Decrypt Payload - AES decryption failed: {e}"));
            CodecError::Decrypt(e.to_string())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests — these are host unit tests (`cargo test --lib`). They cover the
// reviewer's P4A findings #1 and #9 directly: byte-exact round trip,
// MAC verification, version-downgrade rejection, bad magic rejection,
// and malformed envelopes.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    /// Deterministic 32-byte key for tests. NOT a secret — it's the SHA-256
    /// of the string "test-key" in base64. Using a fixed key keeps test
    /// output reproducible.
    fn test_key_b64() -> String {
        // sha256("test-key") → 32 bytes → base64. Pre-computed so tests
        // don't need to call sha2 themselves.
        B64.encode([
            0x9b, 0xa0, 0x44, 0xd2, 0xa0, 0x8f, 0x6b, 0x38,
            0xe2, 0x56, 0x4a, 0xdd, 0xa6, 0x5c, 0x61, 0x6c,
            0x24, 0x21, 0xab, 0x95, 0xf4, 0x23, 0x5a, 0x24,
            0x11, 0xc8, 0xbf, 0x1d, 0xd5, 0x80, 0x75, 0x4a,
        ])
    }

    fn codec() -> Codec {
        Codec::from_b64_key(&test_key_b64()).expect("fixed test key is valid")
    }

    fn ctx() -> TraceCtx<'static> {
        TraceCtx { source: "test" }
    }

    // ---- round-trip ------------------------------------------------------

    /// Issue #9: non-UTF-8 binary bytes must round-trip exactly.
    #[test]
    fn round_trip_binary_bytes() {
        let codec = codec();
        let plaintext: &[u8] = &[0x00, 0xff, 0x80, 0x41, 0x00, 0x7f, 0xc0];
        let envelope = codec.seal(plaintext, &ctx()).expect("seal ok");
        let recovered = codec.open(&envelope, &ctx()).expect("open ok");
        assert_eq!(recovered, plaintext, "binary round trip must be byte-exact");
    }

    /// Standard JSON payload path.
    #[test]
    fn round_trip_json() {
        let codec = codec();
        let plaintext = br#"{"amount":1000,"currency":"INR"}"#;
        let envelope = codec.seal(plaintext, &ctx()).expect("seal ok");
        let recovered = codec.open(&envelope, &ctx()).expect("open ok");
        assert_eq!(recovered, plaintext);
    }

    /// Single-byte and single-block edge cases.
    #[test]
    fn round_trip_single_byte() {
        let codec = codec();
        let envelope = codec.seal(b"x", &ctx()).expect("seal ok");
        assert_eq!(codec.open(&envelope, &ctx()).unwrap(), b"x");
    }

    /// Payload exactly on a block boundary (16 bytes) — PKCS#7 adds a full
    /// padding block. Make sure the codec handles it.
    #[test]
    fn round_trip_block_boundary() {
        let codec = codec();
        let plaintext: &[u8] = &[0xab; 16];
        let envelope = codec.seal(plaintext, &ctx()).expect("seal ok");
        assert_eq!(codec.open(&envelope, &ctx()).unwrap(), plaintext);
    }

    // ---- authenticity (issue #1) -----------------------------------------

    /// Flipping ANY byte of the ciphertext must trigger MAC mismatch, not
    /// a decrypt attempt. This is the primary P4A finding #1.
    #[test]
    fn tampered_ciphertext_byte_rejected() {
        let codec = codec();
        let plaintext = br#"{"amount":1000}"#;
        let envelope = codec.seal(plaintext, &ctx()).unwrap();

        // Decode, flip byte at position 10 (inside the IV), re-encode.
        let mut raw = B64.decode(&envelope).unwrap();
        raw[10] ^= 0x01;
        let tampered = B64.encode(&raw);

        let err = codec.open(tampered.as_bytes(), &ctx()).unwrap_err();
        assert!(
            matches!(err, CodecError::MacMismatch),
            "tampered IV must yield MacMismatch, got {err:?}",
        );
    }

    /// Flipping a byte in the MAC itself must also be rejected.
    #[test]
    fn tampered_mac_rejected() {
        let codec = codec();
        let envelope = codec.seal(b"hello", &ctx()).unwrap();
        let mut raw = B64.decode(&envelope).unwrap();
        let len = raw.len();
        raw[len - 1] ^= 0x01; // last byte is part of the MAC
        let tampered = B64.encode(&raw);
        assert!(matches!(
            codec.open(tampered.as_bytes(), &ctx()).unwrap_err(),
            CodecError::MacMismatch
        ));
    }

    /// Flipping the version byte must be rejected — MAC covers version,
    /// so downgrade attacks produce MacMismatch rather than silently
    /// accepting the altered envelope.
    #[test]
    fn tampered_version_rejected() {
        let codec = codec();
        let envelope = codec.seal(b"hello", &ctx()).unwrap();
        let mut raw = B64.decode(&envelope).unwrap();
        raw[2] = 0x03; // flip version from 0x02 → 0x03
        let tampered = B64.encode(&raw);
        // Could be either UnsupportedVersion (version check runs before
        // MAC) or MacMismatch depending on ordering — both are safe.
        let err = codec.open(tampered.as_bytes(), &ctx()).unwrap_err();
        assert!(
            matches!(err, CodecError::UnsupportedVersion(_) | CodecError::MacMismatch),
            "tampered version must be rejected, got {err:?}",
        );
    }

    // ---- envelope shape --------------------------------------------------

    /// v1-shape envelope (no magic, no MAC) must be rejected outright.
    #[test]
    fn v1_envelope_shape_rejected() {
        let codec = codec();
        // A v1-ish envelope: IV(16) || random ciphertext(16). Not valid
        // base64-of-v2 at all. Expect BadMagic or BadBase64.
        let fake = B64.encode([0u8; 32]);
        let err = codec.open(fake.as_bytes(), &ctx()).unwrap_err();
        assert!(
            matches!(err, CodecError::BadMagic | CodecError::BadBase64),
            "v1-shaped envelope must be rejected, got {err:?}",
        );
    }

    /// Envelope below the minimum size is caught before magic parsing.
    #[test]
    fn tiny_envelope_rejected() {
        let codec = codec();
        let tiny = B64.encode([0u8; 10]);
        let err = codec.open(tiny.as_bytes(), &ctx()).unwrap_err();
        assert!(matches!(err, CodecError::BadBase64), "got {err:?}");
    }

    /// Non-base64 input bails cleanly without panicking.
    #[test]
    fn non_base64_rejected() {
        let codec = codec();
        let err = codec.open(b"not-valid-base64!!!!", &ctx()).unwrap_err();
        assert!(matches!(err, CodecError::BadBase64), "got {err:?}");
    }

    /// Whitespace inside the base64 blob must be tolerated — intermediaries
    /// line-wrap base64 payloads.
    #[test]
    fn whitespace_in_base64_tolerated() {
        let codec = codec();
        let envelope = codec.seal(b"hello", &ctx()).unwrap();
        let wrapped: Vec<u8> = envelope
            .chunks(20)
            .collect::<Vec<_>>()
            .join(&b'\n');
        assert_eq!(codec.open(&wrapped, &ctx()).unwrap(), b"hello");
    }

    // ---- key handling ----------------------------------------------------

    #[test]
    fn invalid_key_length_rejected() {
        // 31 bytes — one short
        let short_key = B64.encode([0u8; 31]);
        assert!(matches!(
            Codec::from_b64_key(&short_key),
            Err(CodecError::KeyLength)
        ));

        // 33 bytes — one too many
        let long_key = B64.encode([0u8; 33]);
        assert!(matches!(
            Codec::from_b64_key(&long_key),
            Err(CodecError::KeyLength)
        ));
    }

    #[test]
    fn empty_key_rejected() {
        assert!(matches!(
            Codec::from_b64_key(""),
            Err(CodecError::KeyLength)
        ));
    }

    /// Issue #1 complement: two different AES keys must produce
    /// unverifiable MACs for each other's envelopes — proves HKDF derives
    /// a distinct MAC key per AES key.
    #[test]
    fn different_keys_do_not_cross_verify() {
        let codec_a = Codec::from_b64_key(&B64.encode([0xaa; 32])).unwrap();
        let codec_b = Codec::from_b64_key(&B64.encode([0xbb; 32])).unwrap();
        let envelope_a = codec_a.seal(b"secret", &ctx()).unwrap();
        let err = codec_b.open(&envelope_a, &ctx()).unwrap_err();
        assert!(matches!(err, CodecError::MacMismatch), "got {err:?}");
    }

    /// Two seals of the same plaintext with the same key must differ (fresh
    /// random IV each time) — otherwise we leak equality of plaintexts.
    #[test]
    fn distinct_iv_per_seal() {
        let codec = codec();
        let plaintext = b"same plaintext";
        let a = codec.seal(plaintext, &ctx()).unwrap();
        let b = codec.seal(plaintext, &ctx()).unwrap();
        assert_ne!(a, b, "two seals of identical plaintext must differ");
        // But both must open to the same plaintext.
        assert_eq!(codec.open(&a, &ctx()).unwrap(), plaintext);
        assert_eq!(codec.open(&b, &ctx()).unwrap(), plaintext);
    }
}
