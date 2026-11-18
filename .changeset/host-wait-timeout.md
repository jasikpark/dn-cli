---
default: patch
---

# Bound `dn host wait` by its `--timeout`

A slow or rate-limited API could keep `dn host wait` running minutes past
`--timeout`, because each check had its own 60-second limit and its own
rate-limit retries. Each check now gets only what is left of the wait (and at
least 5 seconds, so the last check can finish), and a rate limit near the
deadline ends as `ERR_TIMEOUT`.
