# Security policy

## Supported branch

Security fixes are applied to `main` while ULPF is pre-1.0. Tagged releases may be replaced rather than maintained as parallel branches.

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use GitHub’s private vulnerability reporting feature after the private repository is created, or contact the repository owner through the team’s approved private channel. Include the affected commit, impact, reproduction, and any proposed mitigation. Do not include real credentials or sensitive operational logs.

The team will acknowledge a complete report within three working days and provide status within seven working days.

## Deployment guidance

- The console authenticates nobody and binds to `127.0.0.1` by default. It
  refuses cross-origin requests and requests carrying an unexpected `Host`,
  which stops a page the operator has open in another tab from driving it
  (CSRF) and stops a hostile name resolving to loopback (DNS rebinding). That
  is a browser-safety boundary, not a login: anyone who can reach the port can
  write a Source Pack, and a Source Pack decides how every subsequent record is
  interpreted. Place it behind an authenticating reverse proxy before any
  broader exposure.
- `/healthz` and `/readyz` are deliberately outside that guard so an
  orchestrator can probe them. Neither discloses event data; `/readyz` reports
  only pack count, vault writability and schema version.
- Treat `data/integrity/ed25519-signing.key` as a secret. It is excluded from Git; back it up through the team’s secret-management process.
- Pin a trusted public key out of band when verifying checkpoints.
- Do not run the UDP listener on an untrusted interface without network controls and capacity limits appropriate to the deployment.
- Keep raw vaults and normalized output under the same data-classification controls as the original logs.
- Do not commit datasets containing personal, organizational, or operational telemetry.

## Cryptographic scope

The event chain detects modification, deletion, insertion, and reordering inside a stream. Authenticity comes from the persisted Ed25519 checkpoint and a trusted public key. A self-signed checkpoint checked only against its embedded key proves consistency, not identity.
