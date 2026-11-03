---
default: patch
---

# Credentials from before profiles are no longer converted

`dn` used to convert an `auth.json` without a `version` (the single-reference
layout from before 0.2.10) into a `default` profile on every call, and move
`config.json`'s `api_url` into it. Both conversions are gone. Such an
`auth.json` now reads as invalid, with a message to run `dn auth login`, which
replaces it; `config.json` is ignored. If you still have either file, log in
again, passing `--api-url` if you used a non-production API.
