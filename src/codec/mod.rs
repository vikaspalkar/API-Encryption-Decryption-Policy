//! AES-256-CBC codec used by the policy.
//!
//! The on-the-wire format is `base64( iv (16 bytes) || ciphertext )`.
//! Both directions (encrypt and decrypt) are implemented behind a tiny
//! `Codec` facade so the orchestration layer stays symmetrical.

use std::fmt;

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use block_modes::{BlockMode, Cbc};
use block_padding::Pkcs7;

use crate::support::TraceCtx;
use crate::support::log::{emit as trace, Level};

/// AES-256-CBC with PKCS#7 padding.
type Cbc256 = Cbc<Aes256, Pkcs7>;

/// 32 bytes — matches AES-256.
const KEY_BYTES: usize = 32;
/// 16 bytes — AES block size, also the IV length.
const IV_BYTES: usize = 16;

/// Errors raised by [`Codec::seal`] / [`Codec::open`].
#[derive(Debug)]
pub enum CodecError {
    /// Base64-decoded key was not 32 bytes long.
    KeyLength,
    /// Ciphertext was not valid base64.
    BadBase64,
    /// Underlying block-mode library rejected the key/IV pair.
    CipherInit(String),
    /// Padding was incorrect — key mismatch or tampered ciphertext.
    Decrypt(String),
    /// Decrypted bytes were not valid UTF-8.
    NotUtf8(String),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyLength     => f.write_str("Missing or Invalid AES Key"),
            Self::BadBase64     => f.write_str("Base64 decoding failed"),
            Self::CipherInit(e) => write!(f, "Cipher creation failed: {e}"),
            Self::Decrypt(e)    => write!(f, "AES decryption failed: {e}"),
            Self::NotUtf8(e)    => write!(f, "UTF-8 conversion failed: {e}"),
        }
    }
}
impl std::error::Error for CodecError {}

/// A codec bound to a specific AES-256 key.
///
/// Construction validates the key length once so callers don't repeat the
/// check per request.
pub struct Codec {
    key: Vec<u8>,
}

impl Codec {
    /// Decode a base64-encoded 32-byte key and build a codec from it.
    pub fn from_b64_key(b64_key: &str) -> Result<Self, CodecError> {
        let key = B64.decode(b64_key).unwrap_or_default();
        if key.len() != KEY_BYTES {
            return Err(CodecError::KeyLength);
        }
        Ok(Self { key })
    }

    /// Build a fresh CBC instance for a given IV.
    fn cipher(&self, iv: &[u8]) -> Result<Cbc256, CodecError> {
        Cbc256::new_from_slices(&self.key, iv)
            .map_err(|e| CodecError::CipherInit(e.to_string()))
    }

    /// Encrypt plaintext to `base64(iv || ciphertext)`.
    pub fn seal(&self, plaintext: &str, ctx: &TraceCtx<'_>) -> Result<String, CodecError> {
        let mut iv = [0u8; IV_BYTES];
        getrandom::getrandom(&mut iv).expect("Failed to generate IV");

        let cipher = self.cipher(&iv).map_err(|e| {
            trace(ctx, Level::Error, &format!("Encrypt Payload - Cipher creation failed: {e}"));
            e
        })?;

        let ciphertext = cipher.encrypt_vec(plaintext.as_bytes());

        // Pre-size the destination buffer so we avoid a reallocation.
        let mut framed = Vec::with_capacity(IV_BYTES + ciphertext.len());
        framed.extend_from_slice(&iv);
        framed.extend_from_slice(&ciphertext);

        Ok(B64.encode(framed))
    }

    /// Decrypt a `base64(iv || ciphertext)` blob back to a UTF-8 string.
    pub fn open(&self, b64_blob: &str, ctx: &TraceCtx<'_>) -> Result<String, CodecError> {
        let framed = B64.decode(b64_blob).map_err(|_| {
            trace(ctx, Level::Error, "Decrypt Payload - Base64 decoding failed");
            CodecError::BadBase64
        })?;

        if framed.len() < IV_BYTES {
            return Err(CodecError::BadBase64);
        }

        let (iv, ciphertext) = framed.split_at(IV_BYTES);

        let cipher = self.cipher(iv).map_err(|e| {
            trace(ctx, Level::Error, &format!("Decrypt Payload - Cipher creation failed: {e}"));
            e
        })?;

        let plaintext_bytes = cipher.decrypt_vec(ciphertext).map_err(|e| {
            trace(ctx, Level::Error, &format!("Decrypt Payload - AES decryption failed: {e}"));
            CodecError::Decrypt(e.to_string())
        })?;

        String::from_utf8(plaintext_bytes).map_err(|e| {
            trace(ctx, Level::Error, &format!("Decrypt Payload - UTF-8 conversion failed: {e}"));
            CodecError::NotUtf8(e.to_string())
        })
    }
}

/// Strip ASCII whitespace from a base64 blob — line wraps are common in
/// payloads that have been pretty-printed by intermediaries.
pub fn strip_ws(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace()).collect()
}
