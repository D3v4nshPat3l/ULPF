//! Optional encryption at rest for vault block payloads.
//!
//! Without this, a vault segment's compressed blocks are plain zstd frames —
//! anyone with filesystem read access to `--vault` can decompress and read
//! every original log line the collector has ever seen. Encryption is
//! per-block, applied *after* compression (compressing ciphertext gains
//! nothing; zstd needs to see the redundancy encryption erases), and is
//! keyed by an operator passphrase rather than a bare key file, via the same
//! Argon2id-then-AEAD construction `ulpf-cli`'s signing-key encryption uses.
//! The two are deliberately not shared code: the vault crate must not depend
//! on the binary crate that depends on it, so this is its own small copy
//! rather than an import.
//!
//! # What changes on disk, and what does not
//!
//! The block header (`format::BLOCK_HEADER_LEN`, magic/start/ulen/clen/crc)
//! is unchanged. `crc` still covers the *uncompressed* plaintext, computed
//! before compression and encryption — a corrupted ciphertext already fails
//! AEAD authentication, so the CRC's job stays exactly what it always was:
//! catching corruption in the non-encrypted path, and (encrypted or not)
//! catching a zstd round-trip that produced the wrong length. What
//! `clen`/`compressed_len` describes changes meaning slightly: for an
//! encrypted block it is the length of `nonce || ciphertext`, not a bare
//! zstd frame — opaque either way to everything that only forwards bytes by
//! that length, which is everything except this module and `flush_block`.
//!
//! A segment either encrypts every block in it or none of them: that
//! decision is recorded once, in the segment header's `flags` field
//! (bit 0), so a reader never has to guess or trust an external
//! configuration to know how to interpret a given segment's payloads.

use std::io::Write;
use std::path::Path;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

use crate::error::{Result, VaultError};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SALT_FILE_NAME: &str = "vault.salt";

/// A key derived once per `VaultWriter`/`VaultReader`, reused for every block.
pub type Key32 = [u8; 32];

/// Derive a 32-byte cipher key from a passphrase and a stored salt.
///
/// The salt is not secret — only the passphrase is — so persisting it in a
/// plain sidecar file is fine; its only job is making offline brute-force
/// precomputation (rainbow tables) useless across vaults, not hiding
/// anything.
fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Key32> {
    let mut derived = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived)
        .map_err(|e| VaultError::Encryption(format!("deriving vault key from passphrase: {e}")))?;
    Ok(derived)
}

/// Load this vault directory's salt, generating one on first use.
///
/// One salt per vault directory, not per segment: every segment a given
/// `VaultWriter` process ever creates — and every segment a later process
/// reopening the same directory creates — must derive the *same* key from
/// the *same* passphrase, or blocks written in an earlier run become
/// unreadable. Segment numbers advance on every open (see
/// `writer::next_segment_number`); the salt file is what stays constant
/// underneath that.
fn load_or_create_salt(dir: &Path) -> Result<[u8; SALT_LEN]> {
    let path = dir.join(SALT_FILE_NAME);
    match std::fs::read(&path) {
        Ok(bytes) => bytes.try_into().map_err(|_| {
            VaultError::Encryption(format!(
                "{} does not hold exactly {SALT_LEN} bytes; the vault directory is corrupted",
                path.display()
            ))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut salt = [0u8; SALT_LEN];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| VaultError::Encryption(format!("creating {}: {e}", path.display())))?;
            file.write_all(&salt)
                .map_err(|e| VaultError::Encryption(format!("writing {}: {e}", path.display())))?;
            file.sync_all().ok();
            Ok(salt)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost a creation race against another process opening the same
            // vault at the same instant; read what won rather than erroring.
            load_or_create_salt(dir)
        }
        Err(error) => Err(VaultError::Encryption(format!(
            "reading {}: {error}",
            path.display()
        ))),
    }
}

/// Derive this vault's key from `passphrase`, loading or creating its salt.
pub fn key_for_passphrase(dir: &Path, passphrase: &str) -> Result<Key32> {
    let salt = load_or_create_salt(dir)?;
    derive_key(passphrase, &salt)
}

/// Encrypt one block's already-compressed bytes, returning `nonce ||
/// ciphertext` — the exact bytes `flush_block` writes as the block payload.
pub fn encrypt_block(key: &Key32, compressed: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    // `key` is freshly derived per process and never reused across
    // ciphers, and the nonce is fresh per block, so encryption failure here
    // would mean a cipher-internal bug, not a usage error worth a Result.
    let ciphertext = cipher
        .encrypt(nonce, compressed)
        .expect("ChaCha20-Poly1305 encryption does not fail for well-formed input");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Reverse of [`encrypt_block`]: split `nonce || ciphertext` and decrypt back
/// to the compressed (still zstd-encoded) bytes `zstd::decode_all` expects.
pub fn decrypt_block(key: &Key32, stored: &[u8]) -> Result<Vec<u8>> {
    if stored.len() < NONCE_LEN {
        return Err(VaultError::Encryption(
            "encrypted block payload is shorter than one nonce".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = stored.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| {
            VaultError::Encryption(
                "could not decrypt vault block — wrong passphrase, or the block is corrupted"
                    .into(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ulpf-vault-crypto-test-{}-{tag}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = [3u8; 32];
        let plaintext = b"a block's worth of zstd-compressed device logs";
        let stored = encrypt_block(&key, plaintext);
        assert_ne!(
            stored[NONCE_LEN..],
            plaintext[..],
            "must not store plaintext verbatim"
        );
        let recovered = decrypt_block(&key, &stored).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn the_wrong_key_is_refused() {
        let stored = encrypt_block(&[1u8; 32], b"payload");
        assert!(decrypt_block(&[2u8; 32], &stored).is_err());
    }

    #[test]
    fn two_encryptions_of_the_same_bytes_use_different_nonces() {
        // A reused nonce under the same key is catastrophic for this cipher
        // family (it can reveal the XOR of the two plaintexts). Each block
        // must draw its own.
        let key = [5u8; 32];
        let a = encrypt_block(&key, b"same payload");
        let b = encrypt_block(&key, b"same payload");
        assert_ne!(&a[..NONCE_LEN], &b[..NONCE_LEN]);
    }

    #[test]
    fn the_salt_is_stable_across_reopens() {
        let dir = temp_dir("salt-stable");
        let key1 = key_for_passphrase(&dir, "correct horse battery staple").unwrap();
        let key2 = key_for_passphrase(&dir, "correct horse battery staple").unwrap();
        assert_eq!(
            key1, key2,
            "reopening the same vault dir must derive the same key"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn different_passphrases_derive_different_keys_from_the_same_salt() {
        let dir = temp_dir("salt-shared");
        let key1 = key_for_passphrase(&dir, "passphrase one").unwrap();
        let key2 = key_for_passphrase(&dir, "passphrase two").unwrap();
        assert_ne!(key1, key2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
