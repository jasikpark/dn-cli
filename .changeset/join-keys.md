---
default: minor
---

# Create, list, edit, and revoke join keys

A join key is a reusable enrollment token: any number of machines can enroll
with it, each joining as a new host on the key's network with its role, tags,
and address prefixes. `dn join-key create` makes one and prints the token
inside the `dnclient enroll -code <token>` line to run on each machine, the
only time the API shows it; the token is printed only when it looks like one
the API issues. Like `host create`, the network is auto-picked when the
account has exactly one, and on a dual-stack network the IPv4 prefix is sent
so enrolled hosts get an IPv4 address (`--cidr` and `--no-ipv4` override).
`--expires-at` takes an RFC 3339 timestamp in any UTC offset and
`--expires-in` a duration such as `12h`, `7d`, `30d`, or `1y`; both are
checked before any request and sent as UTC.

`dn join-key list` and `dn join-key get` show keys without their tokens,
marking expired ones; `dn join-key edit` renames a key or changes its expiry
(`--no-expiry` removes it); `dn join-key delete` (alias `revoke`) stops a
key from enrolling anything more, after the usual confirmation. `join-keys`,
`join-token`, and `join-tokens` are aliases of `join-key`.

`dn host create` and `dn host enroll-code` now print `dnclient enroll -code <code>`:
`dnclient` takes the code only through its `-code` flag, so the bare form
those commands printed before fails with "-code flag must be set".
