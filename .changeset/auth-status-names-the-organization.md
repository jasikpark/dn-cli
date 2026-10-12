---
default: major
---

# `dn auth status` names the organization and key

`auth status` now asks the API who the key belongs to and shows the organization (with its plan) and the key's name, so a wrong-account key shows up before you run anything against it. `--json` output gains an `owner` object, and an `owner_error` envelope when the lookup fails. If the lookup fails (a rejected key, a failed `op read`, an unreachable API), `auth status` still reports the local setup, then exits 1. `--offline` restores the previous behavior: no API call and no 1Password prompt. Scripts that only need the local setup, or that run where the API or 1Password is unavailable, should pass it.
