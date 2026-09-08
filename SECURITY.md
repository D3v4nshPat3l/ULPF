# Security policy

## Supported branch

Security fixes are applied to `main` while ULPF is pre-1.0. Tagged releases may be replaced rather than maintained as parallel branches.

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use GitHub’s private vulnerability reporting feature after the private repository is created, or contact the repository owner through the team’s approved private channel. Include the affected commit, impact, reproduction, and any proposed mitigation. Do not include real credentials or sensitive operational logs.

The team will acknowledge a complete report within three working days and provide status within seven working days.

## Deployment guidance

- The console requires a bearer token on every `/api/*` route by default,
  generated on first `serve`, stored at `<integrity-dir>/console.token` with
  owner-only file permissions, and printed once at startup. It also refuses
  cross-origin requests and requests carrying an unexpected `Host`, which
  stops a page the operator has open in another tab from driving it (CSRF)
  and stops a hostile name resolving to loopback (DNS rebinding); this second
  check is browser-safety, kept as defense in depth alongside the token, not
  instead of it. `--no-auth` disables the token check for a throwaway local
  demo — with it set, the browser-safety guard is the *only* remaining
  control, and anyone who can reach the port directly can still write a
  Source Pack, which decides how every subsequent record is interpreted. Bind
  to `127.0.0.1` (the default) unless the deployment genuinely needs a wider
  interface, and place a real reverse proxy in front for anything beyond a
  trusted local/lab network regardless.
- Plain HTTP is the console's default. `--tls-self-signed` (a cached,
  self-signed certificate generated on first run) or `--tls-cert`/`--tls-key`
  (an operator-supplied certificate) terminate HTTPS instead. Use one of these
  whenever `--host` binds beyond loopback — otherwise the console token and
  every raw log byte `/api/raw/{locator}` returns cross the network in the
  clear.
- `/healthz` and `/readyz` are deliberately outside both the token and the
  Origin/Host guard so an orchestrator can probe them without a secret.
  Neither discloses event data; `/readyz` reports only pack count, vault
  writability and schema version.
- Treat `data/integrity/ed25519-signing.key` and `data/integrity/console.token`
  as secrets of the same class: whoever reads the signing key can forge a
  checkpoint, and whoever reads the token can act as the console operator.
  Both are excluded from Git and created with owner-only permissions; back
  them up through the team's secret-management process, not by copying them
  into a less-restricted location.
- Neither the vault nor the signing key is encrypted at rest — both rely on
  filesystem permissions alone. Anyone with read access to `--vault` or
  `--integrity-dir` on disk can read raw log content; anyone who can also
  write there and reset permissions could tamper with the key file before the
  next start (which the loose-permission check would then refuse to load, but
  only after the fact). Encrypt the underlying disk/volume, or restrict
  filesystem access, until vault/key encryption ships.
- Pin a trusted public key out of band when verifying checkpoints; a
  checkpoint's `verify_self_signed()` proves internal consistency, not that
  the embedded key is who you think it is.
- Do not run the UDP listener on an untrusted interface without network controls and capacity limits appropriate to the deployment.
- Keep raw vaults and normalized output under the same data-classification controls as the original logs.
- Do not commit datasets containing personal, organizational, or operational telemetry.

## Cryptographic scope

The event chain detects modification, deletion, insertion, and reordering inside a stream. Authenticity comes from the persisted Ed25519 checkpoint and a trusted public key. A self-signed checkpoint checked only against its embedded key proves consistency, not identity.
