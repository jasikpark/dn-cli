---
default: minor
---

# Stream a host's logs with dn host debug logs

`dn host debug logs <host id>` streams the host's dnclient logs for
`--duration` (default 1m, at most 10m) at `--level` (default `info`), printing
each line as it arrives. Under `--json` it prints one JSON object per line
(NDJSON) rather than a single document. The host streams for the whole
duration even if `dn` is stopped early, and reloads its Nebula config when the
session starts and ends. The API key needs the `hosts:debug` permission.
