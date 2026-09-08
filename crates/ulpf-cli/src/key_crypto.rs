//! Encryption at rest for the Ed25519 signing key.
//!
//! Without this, `data/integrity/ed25519-signing.key` is a plain hex-encoded
//! private key protected by nothing but a filesystem permission bit
//! (`integrity_state::ensure_key_is_private`). That is a real control — it
//! stops another user account on the same machine from reading it — but it is
//! not encryption: a stolen disk, a misconfigured backup that preserves file
//! contents but not permissions, or a container image built with the wrong
//! `COPY` order all bypass it while leaving the bytes sitting there in the
//! clear. Whoever reads this file can forge a checkpoint for a rewritten
//! chain, so "protected by 0600" is the whole tamper-evidence guarantee
//! resting on one bit.
//!
//! `--encrypt-key` wraps the 32 raw key bytes in an AEAD envelope keyed by an
//! operator passphrase, turned into a cipher key with Argon2id rather than
//! used directly (a passphrase is not uniformly random the way a key needs to
//! be, and Argon2id's memory-hardness makes brute-forcing a weak passphrase
//! offline expensive even with the ciphertext in hand).
//!
//! Reading is format-sniffed rather than flag-controlled: whichever format is
//! actually on disk is what gets decoded, so toggling `--encrypt-key` between
//! runs cannot accidentally lock a key out or silently misinterpret it. The
//! flag only decides the format used when *creating* a new key.

use anyhow::{bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Serialize, Deserialize)]
struct EncryptedKeyFile {
    /// Bumped if the envelope shape ever changes, so a future reader can tell
    /// an old file from a malformed one instead of guessing.
    version: u8,
    kdf: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// True when `bytes` look like an encrypted key envelope rather than the
/// plain hex format. JSON envelopes start with `{`; a hex-encoded 32-byte key
/// never does, so this is unambiguous without needing a magic byte prefix
/// that would break compatibility with keys already on disk.
pub fn is_encrypted_format(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|&b| b == b'{')
}

/// Derive a 32-byte cipher key from `passphrase` and `salt` with Argon2id.
///
/// Parameters are Argon2id's own defaults (19 MiB memory, 2 iterations, 1
/// lane) rather than a hand-tuned profile: they are OWASP's current minimum
/// recommendation and, unlike a homemade profile, get revisited as the crate
/// updates instead of freezing today's guess about attacker hardware.
fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut derived = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut derived)
        .map_err(|e| anyhow::anyhow!("deriving key from passphrase: {e}"))?;
    Ok(derived)
}

/// Encrypt `key_bytes` under `passphrase`, returning the JSON envelope to
/// write to disk.
pub fn encrypt(passphrase: &[u8], key_bytes: &[u8; 32]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let derived = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, key_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("encrypting signing key"))?;

    let envelope = EncryptedKeyFile {
        version: 1,
        kdf: "argon2id".to_string(),
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    };
    Ok(serde_json::to_vec_pretty(&envelope)?)
}

/// Decrypt an envelope produced by [`encrypt`]. A wrong passphrase and a
/// corrupted file are indistinguishable to an AEAD cipher by design — both
/// fail authentication — so this reports one error for both rather than
/// implying the file itself is at fault.
pub fn decrypt(passphrase: &[u8], envelope_bytes: &[u8]) -> Result<[u8; 32]> {
    let envelope: EncryptedKeyFile =
        serde_json::from_slice(envelope_bytes).context("parsing encrypted key envelope")?;
    if envelope.version != 1 {
        bail!(
            "encrypted key envelope has version {}, which this build does not understand",
            envelope.version
        );
    }
    if envelope.kdf != "argon2id" {
        bail!(
            "encrypted key envelope uses unsupported kdf `{}`",
            envelope.kdf
        );
    }

    let salt: [u8; SALT_LEN] = hex::decode(&envelope.salt)
        .context("salt is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("salt must be {SALT_LEN} bytes"))?;
    let nonce_bytes: [u8; NONCE_LEN] = hex::decode(&envelope.nonce)
        .context("nonce is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be {NONCE_LEN} bytes"))?;
    let ciphertext = hex::decode(&envelope.ciphertext).context("ciphertext is not hex")?;

    let derived = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
        .map_err(|_| {
            anyhow::anyhow!(
                "could not decrypt the signing key — wrong passphrase, or the file is corrupted"
            )
        })?;

    plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted signing key is not 32 bytes"))
}

/// Get the passphrase that guards an encrypted signing key.
///
/// Thin wrapper over [`acquire_passphrase_for`] fixing the env var and
/// prompt label the signing key has always used, so existing call sites and
/// their `ULPF_KEY_PASSPHRASE` documentation stay unchanged.
pub fn acquire_passphrase(confirm: bool) -> Result<String> {
    acquire_passphrase_for("signing key", "ULPF_KEY_PASSPHRASE", confirm)
}

/// Get a passphrase for `label` (used only in prompts/errors), reading
/// `env_var` first.
///
/// The env var takes priority so a scripted deployment (CI, a container
/// entrypoint, the compose files under `deploy/`) can supply it without a
/// TTY. Interactively, `confirm` re-prompts once on creation so a typo does
/// not lock the operator out of a secret that was just generated — there is
/// nothing to confirm against when merely unlocking an existing one.
/// Separate env vars per secret (rather than one shared passphrase) so an
/// operator can protect the signing key and the vault independently, or
/// only one of the two.
pub fn acquire_passphrase_for(label: &str, env_var: &str, confirm: bool) -> Result<String> {
    if let Ok(env) = std::env::var(env_var) {
        if env.is_empty() {
            bail!("{env_var} is set but empty");
        }
        return Ok(env);
    }

    let passphrase = rpassword::prompt_password(format!("{label} passphrase: "))
        .with_context(|| format!("reading passphrase (no TTY and {env_var} is not set)"))?;
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    if confirm {
        let again = rpassword::prompt_password("confirm passphrase: ")
            .context("reading passphrase confirmation")?;
        if again != passphrase {
            bail!("passphrases did not match");
        }
    }
    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key_bytes = [7u8; 32];
        let envelope = encrypt(b"correct horse battery staple", &key_bytes).unwrap();
        assert!(is_encrypted_format(&envelope));

        let recovered = decrypt(b"correct horse battery staple", &envelope).unwrap();
        assert_eq!(recovered, key_bytes);
    }

    #[test]
    fn the_wrong_passphrase_is_refused() {
        let key_bytes = [7u8; 32];
        let envelope = encrypt(b"correct passphrase", &key_bytes).unwrap();

        let error = decrypt(b"wrong passphrase", &envelope)
            .unwrap_err()
            .to_string();
        assert!(error.contains("wrong passphrase, or the file is corrupted"));
    }

    #[test]
    fn a_corrupted_ciphertext_is_refused_the_same_way_as_a_wrong_passphrase() {
        // AEAD authentication failure looks identical whether the passphrase
        // was wrong or the bytes were altered — that indistinguishability is
        // the point (it gives an attacker no oracle to search for either).
        let key_bytes = [7u8; 32];
        let mut envelope = encrypt(b"correct passphrase", &key_bytes).unwrap();
        let as_str = String::from_utf8(envelope.clone()).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&as_str).unwrap();
        let bad_ct = "ff".repeat(48);
        parsed["ciphertext"] = serde_json::json!(bad_ct);
        envelope = serde_json::to_vec(&parsed).unwrap();

        assert!(decrypt(b"correct passphrase", &envelope).is_err());
    }

    #[test]
    fn plain_hex_is_not_mistaken_for_the_encrypted_format() {
        let hex_key = hex::encode([9u8; 32]);
        assert!(!is_encrypted_format(hex_key.as_bytes()));
    }

    #[test]
    fn an_unknown_envelope_version_is_refused_rather_than_misread() {
        let key_bytes = [1u8; 32];
        let envelope = encrypt(b"pw", &key_bytes).unwrap();
        let as_str = String::from_utf8(envelope).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&as_str).unwrap();
        parsed["version"] = serde_json::json!(99);
        let bumped = serde_json::to_vec(&parsed).unwrap();

        let error = decrypt(b"pw", &bumped).unwrap_err().to_string();
        assert!(error.contains("version 99"));
    }
}
