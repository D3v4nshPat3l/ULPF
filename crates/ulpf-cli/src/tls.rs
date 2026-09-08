//! TLS termination for the console.
//!
//! Plain HTTP means every request — including the console token from
//! `crate::auth` and every raw log byte returned by `/api/raw/{locator}` —
//! crosses the network unencrypted and unauthenticated at the transport
//! level. That is a reasonable default on `127.0.0.1` (loopback traffic never
//! leaves the host), and a real gap the moment `--host 0.0.0.0` is used to let
//! a real device or a second machine reach the console, which the demo plan
//! and `docs/3-LAPTOP-DEMO.md` both do.
//!
//! Two ways to get a certificate: bring your own (`--tls-cert`/`--tls-key`),
//! or let the collector generate and cache a self-signed one
//! (`--tls-self-signed`). The self-signed path exists because a lab/demo
//! network has no CA to issue from, and "no TLS" is a worse default than "TLS
//! with a certificate the browser has to click through once."

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;

/// Build the TLS config for the operator-supplied certificate and key.
pub async fn from_files(cert: &Path, key: &Path) -> Result<RustlsConfig> {
    RustlsConfig::from_pem_file(cert, key).await.with_context(|| {
        format!(
            "loading TLS certificate {} / key {}",
            cert.display(),
            key.display()
        )
    })
}

/// Load a cached self-signed certificate under `dir`, generating one on first
/// use.
///
/// Cached rather than regenerated per run: a fresh certificate on every
/// restart would force the operator to re-accept the browser warning every
/// time, which is exactly the kind of friction that makes people click
/// through security prompts without reading them. The private key gets the
/// same owner-only handling as the Ed25519 signing key and console token —
/// this is the same class of secret (whoever holds it can impersonate this
/// collector's TLS endpoint to a browser that already trusts it).
pub async fn self_signed(dir: &Path, hosts: &[String]) -> Result<RustlsConfig> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating TLS state directory {}", dir.display()))?;
    let cert_path = dir.join("console-tls.cert.pem");
    let key_path = dir.join("console-tls.key.pem");

    if !cert_path.exists() || !key_path.exists() {
        generate_and_write(&cert_path, &key_path, hosts)?;
        eprintln!("  generated a self-signed TLS certificate: {}", cert_path.display());
        eprintln!(
            "  the browser will warn about it once; that is expected for a certificate with \
             no public CA behind it, not a sign anything is wrong."
        );
    }

    from_files(&cert_path, &key_path).await
}

fn generate_and_write(cert_path: &PathBuf, key_path: &PathBuf, hosts: &[String]) -> Result<()> {
    let names: Vec<String> = if hosts.is_empty() {
        vec!["localhost".to_string()]
    } else {
        hosts.to_vec()
    };
    let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(names)
        .context("generating self-signed certificate")?;

    write_owner_only(cert_path, cert.pem().as_bytes())?;
    write_owner_only(key_path, key_pair.serialize_pem().as_bytes())?;
    Ok(())
}

/// Write `bytes` to `path`, restricting the file to its owner where the
/// platform supports it. Mirrors `integrity_state::create_key_file` and
/// `auth::create_token_file` rather than introducing a fourth variant of the
/// same pattern.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
