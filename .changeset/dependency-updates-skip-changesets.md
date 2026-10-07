---
default: patch
---

# Dependency updates no longer need a changeset

Renovate PRs carry the `renovate` label, which Knope Bot's changeset check skips; dependency updates ship with the next release without a changelog entry of their own.
