---
default: patch
---

# Bound `dn host wait` by its `--timeout`

A slow or rate-limited API could keep `dn host wait` running well past
`--timeout`, because each check had its own 60-second limit and its own
rate-limit retries. `--timeout` is now a hard limit on how long the command
runs: each check gets only what is left of the wait, and a check that runs out
of that time or a rate limit the wait can't sit out both end as `ERR_TIMEOUT`.

`--timeout` must now be at least `1s` and no shorter than `--interval`; a
shorter one couldn't finish a round trip to the API, or would end before its
second check. A host that checks in during the last `--interval` before the
deadline may be reported as a timeout; a smaller `--interval` narrows that.
