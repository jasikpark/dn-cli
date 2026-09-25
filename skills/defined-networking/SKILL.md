---
name: defined-networking
description: View and manage a Defined Networking (Nebula mesh VPN) network with the `dn` CLI. Use when the user asks about their Defined Networking or Nebula hosts, lighthouses, relays, network, or roles/tags — e.g. "list my hosts", "what's on my mesh network", "is my laptop online" — or wants to add/set up/enroll a new device on their network, or remove one from it.
---

# Defined Networking (`dn`) CLI

`dn` is a command-line client for the [Defined Networking](https://defined.net)
API — the managed [Nebula](https://github.com/slackhq/nebula) mesh VPN. Use it to
inspect and manage the user's network.

## Prerequisite: an API key source must be configured

`dn` never stores the API key itself. It resolves a 1Password secret reference
with `op read` on every call, or reads `DEFINED_API_KEY` from the environment
(raw key or `op://` reference — the environment wins). Check before doing
anything else:

```bash
dn auth status --json
```

`source` is `file`, `env`, `env-ref`, `none`, or `invalid` (a malformed `op://`
reference or a blank `DEFINED_API_KEY`; `message` says which — surface it to
the user). On `none`, stop and ask the
user to run `dn auth login` themselves — it needs their 1Password reference and
an interactive terminal; do not try to prompt for it or pass `--ref` on their
behalf. Every call that resolves an `op://` reference may pop a 1Password unlock
prompt on the user's machine; that is expected.

## Always use `--json` when reading data programmatically

`dn` has two faces:

- **Human** (default): an aligned table meant for a person to read.
- **Agent** (`--json`): machine-readable JSON on **stdout**. Errors also become a
  structured envelope on stdout — `{ "status", "request_id", "errors": [{ "code",
  "message", "path"? }] }` — plus a human hint on stderr.

When **you** (Claude) call `dn`, always pass `--json` and parse stdout. On a
non-zero exit, read the JSON error envelope: `status` is the HTTP code and
`errors[].code` is the machine-stable Defined error code (e.g. `ERR_UNAUTHORIZED`).

## Commands

### List hosts — `dn hosts list`

```bash
dn hosts list --json
```

Returns `{ "data": [ host… ], "metadata": { … } }`, following cursor pagination
to completion (one merged result). Each host includes:

| field | meaning |
|-------|---------|
| `id` | host id (`host-…`) |
| `name` | display name |
| `ipAddresses` | array of overlay IPs (IPv4 and/or IPv6 — dual-stack) |
| `roleID` | assigned role, or `null` |
| `networkID` | the network it belongs to |
| `isLighthouse` / `isRelay` / `isBlocked` | booleans |
| `staticAddresses` | underlay address(es), for lighthouses/relays |
| `tags` | array of `key:value` tags |
| `metadata` | `{ platform, version, lastSeenAt, updateAvailable }` |

Use this to answer questions like "what hosts do I have", "is <device> online"
(check `metadata.lastSeenAt`), "which hosts need an update"
(`metadata.updateAvailable`), or "which are lighthouses".

### Search hosts — `dn hosts search`

```bash
dn hosts search <QUERY> --json
```

Returns the same `{ "data": [ host… ], "metadata": { … } }` shape as
`hosts list`, but only the hosts matching `<QUERY>`. The match is server-side
(`GET /v2/hosts?filter.search=`): a case-insensitive substring across each
host's `name`, `ipAddresses`, assigned role name, and `tags`. The query must be
at least two characters — a shorter one fails locally before any request. Prefer
this over pulling the full list and filtering yourself when the user names a
specific host, IP, role, or tag. Key permission: `hosts:list`.

### Create a host — `dn hosts create`

```bash
dn hosts create <NAME> --json
```

Creates the host **and** its one-time enrollment code in a single call.

| flag | when to pass it |
|------|-----------------|
| `--network <id>` | only when the account has more than one network — otherwise auto-picked. Ids come from `dn networks list --json` |
| `--role <id>` | to skip the account's default (deny-all) role |
| `--lighthouse` | with `--static-address <host:port>` (repeatable) and `--listen-port <port>` |
| `--relay` | with `--listen-port <port>` |
| `--ipv4 <ADDR\|CIDR>` / `--no-ipv4` | to pin an IPv4, or to make a v6-only host |
| `--ipv6 <ADDR>` | to pin an IPv6 |
| `--tags k:v` | repeatable, or comma-separated |
| `--code-lifetime <SECONDS>` | enrollment code lifetime (API default 86400) |

Returns `{ "data": { "host": { … }, "enrollmentCode": { "code", "lifetimeSeconds" } } }`.
Hand the user the code and the exact command to run on the device —
`dnclient enroll <code>` — and tell them it expires (`lifetimeSeconds`). The
human view prints the same thing, plus a reminder that the default role denies
all inbound traffic: nothing can reach a freshly enrolled host until its role
or one of its `--tags` allows it (`dn tags get`). What the new host can reach
depends on the other hosts' rules — run the reachability check under
`roles get` rather than assuming either way.

### Edit a host — `dn hosts edit`

```bash
dn hosts edit <HOST_ID> --role <ROLE_ID> --json
dn hosts edit <HOST_ID> --name <NEW_NAME> --add-tag env:prod --remove-tag env:dev --json
```

| flag | effect |
|------|--------|
| `--role <ROLE_ID>` | assign a firewall role — one way to open a host stuck on the default deny-all role to inbound traffic (a tag with firewall rules is the other) |
| `--clear-role` | unassign the role (sends `roleID: null`); mutually exclusive with `--role` |
| `--name <NAME>` | rename |
| `--add-tag k:v` / `--remove-tag k:v` | repeatable; removes run before adds |

Returns `{ "data": { host… } }` with the updated host. Get role ids from
`dn roles list --json` and host ids from `dn hosts list --json`; never guess
either. An edit that changes nothing skips the write and returns the current
host. Assigning a role or adding/removing a tag changes what traffic the host
can send and receive — a tag brings its own inbound rules and makes the host
match other rules' `allowedTags` — so name the host and the role or tag to the
user before running it.

### Delete a host — `dn hosts delete`

```bash
dn hosts delete <HOST_ID> --yes --json
```

Returns `{ "id": "host-…", "deleted": true }`. Without `--yes`, a `--json` run
fails with an error telling you to pass it — there is no prompt you can answer.

**You MUST confirm with the user before running this**, naming the host
(`dn hosts list --json` gives the id → name mapping). Never infer which host to
delete from context; one id per call.

### List roles — `dn roles list`

```bash
dn roles list --json
```

Returns `{ "data": [ role… ], "metadata": { … } }`. Each role has `id`
(`role-…`), `name`, `description`, `firewallRulesCount`, and `hostCount`. Use
it to find the id for `hosts create --role` or `hosts edit --role`, and to
answer "does this account have a role that allows traffic yet" (a role with
`firewallRulesCount` of 0 allows nothing itself; a host's tags can still
allow traffic).

### Show a role's firewall rules — `dn roles get`

```bash
dn roles get <ROLE_ID> --json
```

Returns `{ "data": role }` — `id`, `name`, `description`, `hostCount`, and
`firewallRules`, an array of inbound rules (`roles list` has only a count).
Each rule has `protocol` (`ANY`, `TCP`, `UDP`, `ICMP`), `portRange`
(`{from, to}`, or `null` for every port; Nebula also treats a range starting
at `0` as every port), `description`, and the allowed
source: `allowedRoleID` (`null` for any host, with or without a role) and
`allowedTags` (`null` or a list; a host must carry every tag). When both are
set, a source host needs the role *and* all the tags. An empty
`firewallRules` means the role itself allows no inbound traffic.

A role is not a host's only source of inbound rules: each of a host's tags
can carry firewall rules too, and the host accepts the union. Read them with
`dn tags get` (below) for each tag on the host before calling it
unreachable — a host with no role may still accept traffic through its
tags.

Use it to answer "can host A reach port N/protocol P on host B": find B's
role and tags, then look across their rules for one whose protocol is P or
`ANY`, whose port range covers N, is `null`, or starts at `0`, and whose
source matches A —
A's role when `allowedRoleID` is set, and every tag in `allowedTags`. For
P = ICMP, ports don't apply but the range still matters: an `ICMP` rule
always matches, while an `ANY` rule matches only when its range is `null` or
starts at `0` (`ANY` on port 22 does not allow ping). A match means yes,
provided neither A nor B `isBlocked` — a blocked host is off the mesh
whatever the rules say.
"No" needs a successful read of B's role (if it has one) and of every tag on
B: if any `roles get` or `tags get` fails (a missing `tags:read` permission,
a 404), or returns a `data` that isn't an object or has no `firewallRules`
list, answer "unknown" and name what couldn't be read — `--json` passes the
response through without checking it.

Without `--json`, rules print sorted the way the admin panel shows them, and
a warning appears when one rule allows all hosts on any protocol and port,
since that makes the rest redundant.

### Show a tag's firewall rules — `dn tags get`

```bash
dn tags get <KEY:VALUE> --json
```

Returns `{ "data": tag }` — `name`, `description`, `hostCount`, `priority`,
`configOverrides`, `routeSubscriptions`, and `firewallRules`, the inbound
rules added to every host carrying the tag, in the same shape as a role's.
An empty `firewallRules` means the tag adds nothing; the host's role and
other tags still apply. Human output shows the description, host count,
priority, and the rule table laid out like `roles get`, and warns on any rule
allowing all hosts on any protocol and port, since it opens every host with
the tag; use `--json` for config overrides and route subscriptions. Key
permission: `tags:read`.

### List networks — `dn networks list`

```bash
dn networks list --json
```

Returns `{ "data": [ network… ], "metadata": { … } }`. Each network has `id`
(`network-…`), `name`, `description`, `cidrs` (the overlay prefixes — an IPv6
one and, on dual-stack networks, an IPv4 one), `hostCount`, `curve` (`25519`
or `P256`), `certVersion`, and two lighthouse settings that live on the
network, not on any host:

| field | meaning |
|-------|---------|
| `disableManagedLighthouses` | `false` means Defined's managed lighthouses back the network. They are not hosts, so `hosts list` never shows them — a network with no lighthouse host is still fine when this is `false`. |
| `lighthousesAsRelays` | `true` means the network's self-hosted lighthouses also act as relays. |

Use it to find the id for `hosts create --network`, and to answer "how do my
hosts find each other" or "do I have relays" — check these flags before
concluding anything from the hosts list alone.

## Safety

| operation | gate |
|-----------|------|
| `hosts list`, `hosts search`, `roles list`, `roles get`, `tags get`, `networks list` | free — reads change nothing |
| `hosts edit` | a write: renaming is cosmetic, but `--role`, `--clear-role`, `--add-tag`, and `--remove-tag` change the host's firewall. Confirm the host and the role or tag with the user first. |
| `hosts create` | a write: it creates a billable host and a one-time enrollment code. Confirm the name, the network, and any `--role` or `--tags` with the user first — like `hosts edit`, a role or tag sets the new host's firewall. |
| `hosts delete` | destructive and irreversible: the device loses network access, and getting it back means creating a new host and re-enrolling. Always get explicit user confirmation for the specific host. |

## Where this is going (not built yet)

Role writes are still missing: `roles create` / `roles add-rule`. The
account's default role denies all inbound traffic, so nothing can reach a
host enrolled via `hosts create` until a role with firewall rules exists
and is assigned, or it carries a tag with firewall rules. `dn roles list`
shows whether such a role already exists, and `hosts edit --role` assigns it; creating the role itself still happens in
the admin panel. Say so rather than promising two hosts will reach each other.
