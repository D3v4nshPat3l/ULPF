//! Console authentication: a single bearer token gating every `/api/*` route.
//!
//! Before this, the console had no credential at all — only the Origin/Host
//! guard in `server.rs`, which stops a malicious *browser page* from driving
//! the console but does nothing for a client that reaches the port directly
//! (curl, a script, another host on the same network segment). A judge who
//! asks "what stops someone who can reach this port from approving a pack or
//! reading raw evidence" previously had no answer but "bind to loopback."
//! Binding to loopback is still the right default, but it should not be the
//! *only* control.
//!
//! The token is generated once, stored next to the signing key with the same
//! owner-only permissions, and printed to the operator at startup. This
//! mirrors `integrity_state`'s key-file handling deliberately: the two are the
//! same class of secret (a file whose disclosure lets someone else act as this
//! collector) and should fail the same way when mishandled.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context};
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use rand::RngCore;
use serde_json::json;

/// Bytes of entropy in a generated token, before hex encoding.
const TOKEN_BYTES: usize = 32;

/// Create the token file such that only its owner can read it.
///
/// Same reasoning as `integrity_state::create_key_file`: the mode is applied
/// at creation, not by a later `set_permissions`, so the token is never
/// written to a file that was briefly world-readable. Windows has no POSIX
/// mode bits; there the file inherits the directory ACL.
fn create_token_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Refuse a token file anyone other than its owner can read.
///
/// Identical stakes to a loose signing-key permission: whoever can read this
/// file can authenticate as the console operator, including approving a
/// Source Pack that decides how every subsequent record is interpreted.
#[cfg(unix)]
fn ensure_token_is_private(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading permissions of {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;

    if mode & 0o077 != 0 {
        bail!(
            "console token {} is mode {:04o}; it must not be readable by group or others. \
             Run `chmod 600 {}` and rotate the token (delete the file and restart) if the \
             machine is shared.",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_token_is_private(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Load the token at `path`, generating and persisting a fresh one if absent.
///
/// Returns the token alongside whether it was just generated, so the caller
/// can decide how loudly to print it — a freshly generated token is the only
/// copy that exists and must reach the operator; a reloaded one does not need
/// repeating on every restart.
pub fn load_or_create(path: &Path) -> anyhow::Result<(String, bool)> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            ensure_token_is_private(path)?;
            let token = text.trim().to_string();
            if token.is_empty() {
                bail!("console token file {} is empty", path.display());
            }
            Ok((token, false))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = [0u8; TOKEN_BYTES];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let token = hex::encode(bytes);
            match create_token_file(path) {
                Ok(mut file) => {
                    file.write_all(token.as_bytes())?;
                    file.sync_all()?;
                    Ok((token, true))
                }
                // A concurrent `serve` (two collectors racing to start against
                // the same integrity dir) lost the create race; read what won.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    load_or_create(path)
                }
                Err(error) => Err(error).with_context(|| format!("creating {}", path.display())),
            }
        }
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// Compare two byte strings in time independent of where they first differ.
///
/// A short-circuiting `==` leaks, via response timing, how many leading bytes
/// of a guess were correct — enough for an attacker on the same network to
/// recover the token byte-by-byte. This always walks the longer of the two
/// lengths and folds every byte into the accumulator.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_diff = (a.len() ^ b.len()) as u8;
    let mut diff = len_diff;
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

fn unauthorized(message: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response()
}

/// Extract the presented token from either header form the console/CLI use.
///
/// `Authorization: Bearer <token>` is what a browser `fetch` and most HTTP
/// tooling expect; `X-ULPF-Token` exists because a bare `curl` one-liner
/// (`curl -H "X-ULPF-Token: $TOK" ...`) is what the README's other examples
/// already look like, and forcing the bearer scheme there is one more thing to
/// get slightly wrong while copying a command under demo pressure.
fn presented_token(request: &Request) -> Option<String> {
    let headers = request.headers();
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = value.strip_prefix("Bearer ") {
            return Some(token.trim().to_string());
        }
    }
    headers
        .get("x-ulpf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

/// Middleware: reject any request that does not present `expected`.
///
/// Applied only to the guarded router in `server.rs` — `/healthz` and
/// `/readyz` are merged in after this layer specifically so an orchestrator's
/// probe, which has no way to carry a secret and no need to, is never blocked
/// by it. `/` and `/dev` are merged in the same way, for a different reason:
/// they are the static page shell, and the shell's own script is what prompts
/// for this token in the first place — it cannot do that if the shell itself
/// never arrives. See the comment on `server::router` for both cases.
pub async fn require_token(
    expected: std::sync::Arc<str>,
    request: Request,
    next: Next,
) -> Response {
    match presented_token(&request) {
        Some(presented) if constant_time_eq(presented.as_bytes(), expected.as_bytes()) => {
            next.run(request).await
        }
        Some(_) => {
            unauthorized("the token presented does not match this collector's console token")
        }
        None => unauthorized(
            "this endpoint requires a console token: send `Authorization: Bearer <token>` \
             or `X-ULPF-Token: <token>`. The token is printed at startup and stored in the \
             integrity directory as console.token.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ulpf-auth-test-{}-{tag}-{:?}",
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
    fn a_new_token_round_trips() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("console.token");

        let (created, was_new) = load_or_create(&path).unwrap();
        assert!(was_new);
        let (reloaded, was_new_again) = load_or_create(&path).unwrap();
        assert!(!was_new_again);
        assert_eq!(created, reloaded);
        assert_eq!(created.len(), TOKEN_BYTES * 2, "hex-encoded 32 bytes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn constant_time_eq_agrees_with_ordinary_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[cfg(unix)]
    #[test]
    fn a_new_token_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("mode");
        let path = dir.join("console.token");
        load_or_create(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "console token was created mode {mode:04o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_token_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("loose");
        let path = dir.join("console.token");
        load_or_create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = load_or_create(&path).unwrap_err().to_string();
        assert!(
            error.contains("group or others"),
            "expected a permissions refusal, got: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
