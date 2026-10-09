---
default: minor
---

# `delete --yes` names what it deleted

`dn host delete`, `dn role delete`, and `dn network delete` with `--yes` now look the resource up first, so the result reads `Deleted host "Build Server" (host-…)` instead of the bare id. The lookup is best-effort: a key without the read scope still deletes, and the result names the id alone. `--json` output is unchanged and makes no lookup.
