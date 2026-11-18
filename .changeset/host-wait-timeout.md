---
default: patch
---

# Bound `dn host wait` by its `--timeout`

A slow or rate-limited API could keep `dn host wait` running well past
`--timeout`, because each check had its own 60-second limit and its own
rate-limit retries. Each check now gets only what is left of the wait, a
check that runs out of that time or a rate limit the wait can't sit out both
end as `ERR_TIMEOUT`, and a very large `--timeout` no longer risks a panic.
