---
default: patch
---

# Validate `host create` arguments locally and preserve commas in `--tag`

`dn host create` now validates `name`, `--network`, `--role`, and `--tag`
before resolving credentials or contacting the API, matching the other host
commands.

The tag flag on `host create` is now `--tag` (with `--tags` kept as an alias)
and no longer splits values on commas, so tag values containing commas (such as
`splice:by,comma`) work the same way as in `host edit --add-tag`, `host list --tag`,
and `join-key create --tag`. Pass `--tag` once per tag instead of separating
multiple tags with commas.

Also caps `Retry-After` delays above 60 seconds at 60 seconds instead of
falling back to a 1-second backoff, and skips no-op `host edit` writes when the
API returns `tags: null`.
