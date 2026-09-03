//! Persistent signing key and signed chain checkpoint management.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ulpf_ocsf::types::HashAlgorithm;
use ulpf_ocsf::{Attestor, ChainLink, Checkpoint};

pub struct IntegrityRuntime {
    pub attestor: Attestor,
    pub checkpoint_path: PathBuf,
    pub public_key_path: PathBuf,
    pub resume_anchor: Option<ChainLink>,
}

pub fn open(
    dir: &Path,
    authority_uid: &str,
    chain_uid: &str,
    hash: HashAlgorithm,
) -> anyhow::Result<IntegrityRuntime> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating integrity state directory {}", dir.display()))?;

    let key_path = dir.join("ed25519-signing.key");
    let public_key_path = dir.join("ed25519-signing.pub");
    let checkpoint_path = dir.join(format!("{}.checkpoint.json", safe_name(chain_uid)));
    let key = load_or_create_key(&key_path)?;
    write_synced(
        &public_key_path,
        hex::encode(key.verifying_key().to_bytes()).as_bytes(),
    )?;

    let stored = load_checkpoint(&checkpoint_path)?;
    let (resume_anchor, sequence) = match stored {
        Some(checkpoint) => {
            checkpoint
                .verify_with(&key.verifying_key())
                .context("the stored checkpoint signature is invalid")?;
            if checkpoint.authority_uid != authority_uid || checkpoint.chain_uid != chain_uid {
                bail!(
                    "stored checkpoint belongs to authority `{}` / chain `{}`, not `{authority_uid}` / `{chain_uid}`",
                    checkpoint.authority_uid,
                    checkpoint.chain_uid
                );
            }
            if checkpoint.head.algorithm_id != hash.algorithm_id() as u8
                || checkpoint.head.algorithm.as_deref() != hash.algorithm_name()
            {
                bail!(
                    "chain `{chain_uid}` already uses a different hash algorithm; choose another --chain or keep the original algorithm"
                );
            }
            let sequence = checkpoint.sequence;
            let anchor = ChainLink {
                uid: checkpoint.head_uid,
                type_uid: checkpoint.head_type_uid,
                fingerprint: checkpoint.head,
            };
            (Some(anchor), sequence)
        }
        None => (None, 0),
    };

    let mut attestor = Attestor::new(authority_uid, chain_uid)
        .with_hash(hash)
        .with_signing_key(key);
    if let Some(anchor) = resume_anchor.clone() {
        attestor = attestor.resume_from(anchor, sequence);
    }

    Ok(IntegrityRuntime {
        attestor,
        checkpoint_path,
        public_key_path,
        resume_anchor,
    })
}

pub fn persist_checkpoint(path: &Path, checkpoint: &Checkpoint) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(checkpoint)?;
    write_synced(path, &bytes)
        .with_context(|| format!("persisting signed checkpoint to {}", path.display()))
}

pub fn read_checkpoint(path: &Path) -> anyhow::Result<Checkpoint> {
    load_checkpoint(path)?.with_context(|| format!("checkpoint {} does not exist", path.display()))
}

pub fn read_public_key(path: &Path) -> anyhow::Result<ed25519_dalek::VerifyingKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading public key {}", path.display()))?;
    let bytes: [u8; 32] = hex::decode(text.trim())
        .context("public key is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must contain exactly 32 bytes"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 public key")
}

fn load_checkpoint(path: &Path) -> anyhow::Result<Option<Checkpoint>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
                format!("parsing checkpoint {}", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading checkpoint {}", path.display())),
    }
}

/// Create the signing-key file such that only its owner can read it.
///
/// The mode is applied by `open(2)` at creation time rather than by a later
/// `set_permissions` call, so the key bytes are never written to a file that
/// was briefly world-readable.
///
/// Windows has no POSIX mode bits; there the file inherits the directory ACL,
/// which for a per-user data directory is already owner-scoped.
fn create_key_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Refuse to use a signing key that anyone other than its owner can read.
///
/// This key is the sole secret behind every signed checkpoint. Whoever can read
/// it can forge a checkpoint for an altered chain, so a permissive mode voids
/// the integrity guarantee rather than merely weakening it. Failing loudly is
/// better than signing with a key the container image may have shipped
/// world-readable.
#[cfg(unix)]
fn ensure_key_is_private(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading permissions of {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;

    if mode & 0o077 != 0 {
        bail!(
            "signing key {} is mode {:04o}; it must not be readable by group or others. \
             Run `chmod 600 {}` and rotate the key if the machine is shared.",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_key_is_private(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn load_or_create_key(path: &Path) -> anyhow::Result<SigningKey> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            ensure_key_is_private(path)?;
            let bytes: [u8; 32] = hex::decode(text.trim())
                .context("signing key is not hex")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("signing key must contain exactly 32 bytes"))?;
            Ok(SigningKey::from_bytes(&bytes))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = SigningKey::generate(&mut OsRng);
            let encoded = hex::encode(key.to_bytes());
            match create_key_file(path) {
                Ok(mut file) => {
                    file.write_all(encoded.as_bytes())?;
                    file.sync_all()?;
                    Ok(key)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    load_or_create_key(path)
                }
                Err(error) => Err(error).with_context(|| format!("creating {}", path.display())),
            }
        }
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn safe_name(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ulpf-key-test-{}-{tag}-{:?}",
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
    fn a_new_key_round_trips() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("signing.key");

        let created = load_or_create_key(&path).unwrap();
        let reloaded = load_or_create_key(&path).unwrap();

        assert_eq!(created.to_bytes(), reloaded.to_bytes());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_key_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("mode");
        let path = dir.join("signing.key");
        load_or_create_key(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "signing key was created mode {mode:04o}; anyone able to read it can forge checkpoints"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("loose");
        let path = dir.join("signing.key");
        load_or_create_key(&path).unwrap();

        // Simulate a key restored from a backup or baked into an image with
        // default permissions.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = load_or_create_key(&path).unwrap_err().to_string();
        assert!(
            error.contains("group or others"),
            "expected a permissions refusal, got: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
