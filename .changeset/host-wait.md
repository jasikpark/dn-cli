---
default: minor
---

# Wait for a host to check in with `dn host wait`

`dn host wait <host id>` polls a host until it has checked in with Defined
Networking, then shows it: the end of setting up a device with `dn host create`
and `dnclient enroll`. `--timeout` (default 10m) and `--interval` (default 5s)
take durations like `90s` or `1h`; `--since now` waits for a fresh check-in
when re-enrolling a host that was seen before. A wait that runs out of time
exits 1 with `ERR_TIMEOUT` under `--json`.
