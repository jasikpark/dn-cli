---
default: minor
---

# Find a host by exact name or IP, and search from `host list`

`dn host list` and `dn host search` take two more of the filters
`GET /v2/hosts` offers: `--name` keeps the host with exactly that name
(case-sensitive) and `--ip` the host with that overlay IPv4 or IPv6 address.
Add `--network` to either and at most one host comes back. `--ip` is checked
locally, so a value that isn't an IP address fails before any request.

`dn host list` also takes `--search <QUERY>`, so the search shows up beside
the other filters in `dn host list --help`. `dn host search <QUERY>` is the
same request with the query as a positional argument.
