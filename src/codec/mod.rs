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
