# OCSF schema provenance

This directory is a vendored, unmodified snapshot of the Open Cybersecurity
Schema Framework schema.

| Field | Value |
|---|---|
| Upstream | <https://github.com/ocsf/ocsf-schema> |
| Version | 1.9.0 |
| Commit | `856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba` |
| License | Apache-2.0 (see this directory's `LICENSE`) |

The snapshot is committed directly instead of retained as a nested Git
repository or submodule, so fresh clones and air-gapped deployments have a
stable schema without an additional checkout step.

To update it, review the upstream release notes, replace this snapshot, update
the version and commit above, then run the complete test and pack-validation
gates. Schema updates must be isolated in their own pull request.

