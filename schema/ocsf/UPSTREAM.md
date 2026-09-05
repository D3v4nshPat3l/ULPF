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

## Why the upstream project's own files are still here

This directory contains files ULPF never reads: the OCSF project's `.github`
workflows and linters, its `CHANGELOG.md`, `CONTRIBUTING.md`, `README.md`, and
its `templates/`. Roughly twenty files that look like cruft.

They are kept because *unmodified* is the property that makes this snapshot
worth anything. Anyone can clone `ocsf-schema` at commit
`856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba` and diff it against this directory.
The only difference should be this file, which upstream does not have — every
other path identical proves nobody quietly edited an enum value or a class
definition on the way in. Deleting the parts we do not use would save about a
hundred kilobytes and forfeit that check.

```bash
git clone https://github.com/ocsf/ocsf-schema /tmp/ocsf
git -C /tmp/ocsf checkout 856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba
diff -r --exclude=.git /tmp/ocsf schema/ocsf   # expect: only UPSTREAM.md
```

For a framework whose central claim is that its records can be verified, the
schema those records are validated against should be verifiable too.
`tools/audit_pack_enums.py` reads this snapshot on every CI run for exactly
that reason.

