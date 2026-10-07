---
name: defined-networking
description: View and manage a Defined Networking (Nebula mesh VPN) network with the `dn` CLI. Use when the user asks about their Defined Networking or Nebula hosts, lighthouses, relays, network, or roles/tags — e.g. "list my hosts", "what's on my mesh network", "is my laptop online" — or wants to add/set up/enroll a new device on their network, remove one from it, delete a role, tag, or network, or find out who changed something and when (the audit log).
---

# Defined Networking (`dn`) CLI

`dn` is a command-line client for the [Defined Networking](https://defined.net)
API — the managed [Nebula](https://github.com/slackhq/nebula) mesh VPN. Use it to
inspect and manage the user's network.

## Prerequisite: an API key source must be configured

Each profile's key is in the OS keyring, or is a 1Password secret reference
that `dn` resolves with `op read` on every call; `DEFINED_API_KEY` in the
environment (raw key or `op://` reference) overrides either. Check before
doing anything else:

```bash
dn auth status --json
```

`source` is `keyring`, `file` (a 1Password reference), `env`, `env-ref`, `none`,
or `invalid` (a malformed `op://`
reference, a blank `DEFINED_API_KEY`, or a missing profile; `message` says
which — surface it to the user). `profile` names the profile (account) in use
and `api_url` the server it talks to; anything other than
`https://api.defined.net` is a test or mock server, so say so when you report
results. On `none`, stop and ask the
user to run `dn auth login` themselves — it needs their API key and an
interactive terminal; never ask them to paste a key into the conversation, and
do not pass `--key-stdin` or `--ref` on their behalf. Every call that resolves
an `op://` reference may pop a 1Password unlock prompt on the user's machine,
and a locked keyring may prompt to unlock; that is expected. If a call fails
with "no OS keyring is available", the machine has no keyring (e.g. headless
Linux): tell the user to use `--ref` or `DEFINED_API_KEY` instead.
`source: "keyring"` only says where the key should be; `auth status` doesn't
open the keyring. If a call fails with "has no key in the OS keyring", relay
that error's `dn auth login --profile …` command to the user; don't run it.

### Profiles

Credentials are stored as named profiles (`dn auth list --json`), e.g. `prod`
and `staging` with different API URLs. When the user names an environment,
pass `--profile <name>` on every call (or set `DN_PROFILE` for your shell).
**Never run `dn auth switch`, `login` or `logout`** — each can change the
default profile for every other process, including other agents running in
parallel. If the user asks to add a profile, give them the
`dn auth login --profile <name>` command to run, with `--keep-default` unless
they want it to become the default. `dn auth list --json` gives each profile's
`key_source` (`keyring`, `file`, or `null` with no key) and its `api_key_ref`
(the `op://` reference, else `null`). When the user has logged out or
switched a profile to `--ref`, a non-empty `keyring_left` in that command's
output names profiles whose old keyring entry couldn't be deleted; tell them.

## Always use `--json` when reading data programmatically

`dn` has two faces:

- **Human** (default): an aligned table meant for a person to read.
- **Agent** (`--json`): machine-readable JSON on **stdout**. Errors also become a
  structured envelope on stdout — `{ "status", "request_id", "errors": [{ "code",
  "message", "path"? }] }` — plus a human hint on stderr.

When **you** (Claude) call `dn`, always pass `--json` and parse stdout. On a
non-zero exit, read the JSON error envelope. It has the same keys whatever
failed; branch on `errors[].code`:

- **API errors** (exit 1): `status` is the HTTP code and `errors[].code` is the
  machine-stable Defined error code (e.g. `ERR_UNAUTHORIZED`). A response
  without that shape (e.g. a proxy's 502) becomes `ERR_HTTP_<status>` with the
  raw body as the message. When `dn` knows more than the API said, the message
  starts with it — e.g. which flag skips the call that failed.
- **Local errors** (exit 1): `status` and `request_id` are `null` because the
  request never reached the API.
  - `ERR_INVALID_ARGUMENT`: `dn` rejected the arguments — a malformed value, or
    a flag you must add (`--yes`, `--network`). Fix the command; the message
    says how. (An `auth login` that needs `--key-stdin` or `--ref` is for the
    user to run, not you.)
  - `ERR_LOCAL`: anything else — credentials, config, or the network.
- **Usage errors** (exit 2): `ERR_USAGE` — an unknown subcommand or flag, or a
  missing argument. Check `dn <command> --help`: the installed `dn` may be
  older than this skill.

### Pagination

Every `list` and `host search` returns **one page**: up to 500 items by
default (`--limit 1..500`, alias `--page-size`). `metadata.hasNextPage` / `hasPrevPage` say
whether more exist, and `metadata.nextCursor` / `prevCursor` fetch them:
rerun the same command, same filters, with `--cursor=<nextCursor>` (a later
`--cursor` replaces an earlier one). Without `--json`, stderr prints the
full command for each neighbouring page, ready to run. Check `hasNextPage` before concluding something doesn't exist — a
501st host is on page two.

A cursor carries the position, not the filters: repeat every argument
(`--target`, the search query) or the next call pages through the unfiltered
list. A cursor the API doesn't recognize — cut short, or from another
command — returns the **first** page, not an error; after following a
`nextCursor`, `hasPrevPage: false` means that happened.

## Commands

### List hosts — `dn host list`

```bash
dn host list --json
```

Returns one page of `{ "data": [ host… ], "metadata": { … } }` (see
Pagination). Each host includes:

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

### Show one host — `dn host get`

```bash
dn host get <HOST_ID> --json
```

Returns `{ "data": host, "metadata": {} }`: one host with the same fields as a
`host list` entry. Use it when you already have the id; for fields across many
hosts, one `host list` beats a `host get` per host. Without `--json` it also looks up the
role's name, which needs `roles:read`; a key without it shows the role id
instead. Key permission: `hosts:read`.

### Search hosts — `dn host search`

```bash
dn host search <QUERY> --json
```

Returns the same `{ "data": [ host… ], "metadata": { … } }` shape as
`host list`, but only the hosts matching `<QUERY>`. The match is server-side
(`GET /v2/hosts?filter.search=`): a case-insensitive substring across each
host's `name`, `ipAddresses`, assigned role name, and `tags`. The query must be
at least two characters — a shorter one fails locally before any request. Prefer
this over pulling the full list and filtering yourself when the user names a
specific host, IP, role, or tag. Key permission: `hosts:list`.

### Create a host — `dn host create`

```bash
dn host create <NAME> --json
```

Creates the host **and** its one-time enrollment code in a single call.

| flag | when to pass it |
|------|-----------------|
| `--network <id>` | only when the account has more than one network — otherwise auto-picked. Ids come from `dn network list --json` |
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
or one of its `--tags` allows it (`dn tag get`). What the new host can reach
depends on the other hosts' rules — run the reachability check under
`role get` rather than assuming either way.

### Edit a host — `dn host edit`

```bash
dn host edit <HOST_ID> --role <ROLE_ID> --json
dn host edit <HOST_ID> --name <NEW_NAME> --add-tag env:prod --remove-tag env:dev --json
```

| flag | effect |
|------|--------|
| `--role <ROLE_ID>` | assign a firewall role — one way to open a host stuck on the default deny-all role to inbound traffic (a tag with firewall rules is the other) |
| `--clear-role` | unassign the role (sends `roleID: null`); mutually exclusive with `--role` |
| `--name <NAME>` | rename |
| `--add-tag k:v` / `--remove-tag k:v` | repeatable; removes run before adds |

Returns `{ "data": { host… } }` with the updated host. Get role ids from
`dn role list --json` and host ids from `dn host list --json`; never guess
either. An edit that changes nothing skips the write and returns the current
host. Assigning a role or adding/removing a tag changes what traffic the host
can send and receive — a tag brings its own inbound rules and makes the host
match other rules' `allowedTags` — so name the host and the role or tag to the
user before running it.

### Delete a host — `dn host delete`

```bash
dn host delete <HOST_ID> --yes --json
```

Returns `{ "id": "host-…", "deleted": true }`. Without `--yes`, a `--json` run
fails with an error telling you to pass it — there is no prompt you can answer.

**You MUST confirm with the user before running this**, naming the host
(`dn host list --json` gives the id → name mapping). Never infer which host to
delete from context; one id per call.

### List roles — `dn role list`

```bash
dn role list --json
```

Returns `{ "data": [ role… ], "metadata": { … } }`. Each role has `id`
(`role-…`), `name`, `description`, `firewallRulesCount`, and `hostCount`. Use
it to find the id for `host create --role` or `host edit --role`, and to
answer "does this account have a role that allows traffic yet" (a role with
`firewallRulesCount` of 0 allows nothing itself; a host's tags can still
allow traffic).

### Show a role's firewall rules — `dn role get`

```bash
dn role get <ROLE_ID> --json
```

Returns `{ "data": role }` — `id`, `name`, `description`, `hostCount`, and
`firewallRules`, an array of inbound rules (`role list` has only a count).
Each rule has `protocol` (`ANY`, `TCP`, `UDP`, `ICMP`), `portRange`
(`{from, to}`, or `null` for every port; Nebula also treats a range starting
at `0` as every port), `description`, and the allowed
source: `allowedRoleID` (`null` for any host, with or without a role) and
`allowedTags` (`null` or a list; a host must carry every tag). When both are
set, a source host needs the role *and* all the tags. An empty
`firewallRules` means the role itself allows no inbound traffic.

A role is not a host's only source of inbound rules: each of a host's tags
can carry firewall rules too, and the host accepts the union. Read them with
`dn tag get` (below) for each tag on the host before calling it
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
B: if any `role get` or `tag get` fails (a missing `tags:read` permission,
a 404), or returns a `data` that isn't an object or has no `firewallRules`
list, answer "unknown" and name what couldn't be read — `--json` passes the
response through without checking it.

Without `--json`, rules print sorted the way the admin panel shows them, and
a warning appears when a rule allows all hosts on any protocol and port,
since every host with the role then accepts all inbound traffic.

### Delete a role — `dn role delete`

```bash
dn role delete <ROLE_ID> --yes --json
```

Returns `{ "id": "role-…", "deleted": true }`. Same `--yes` rule as
`host delete`. Key permission: `roles:delete`.

**You MUST confirm with the user before running this**, naming the role and
how many hosts it is assigned to (`hostCount` from `dn role list --json`).
The API docs don't say what happens to hosts still assigned the role (it may
refuse, or unassign it), so treat any traffic its rules allowed as at risk;
a refusal comes back as an API error. One id per call.

### List tags — `dn tag list`

```bash
dn tag list --json
```

Returns `{ "data": [ tag… ], "metadata": { … } }`. Each tag has `name`
(`key:value`), `description`, `priority`, `hostCount`, `firewallRulesCount`,
`configOverrides`, and `routeSubscriptions`. Use it to find which tags carry
firewall rules (`firewallRulesCount` above 0) before calling `dn tag get` on
them. Key permission: `tags:list`.

### Show a tag's firewall rules — `dn tag get`

```bash
dn tag get <KEY:VALUE> --json
```

Returns `{ "data": tag }` — `name`, `description`, `hostCount`, `priority`,
`configOverrides`, `routeSubscriptions`, and `firewallRules`, the inbound
rules added to every host carrying the tag, in the same shape as a role's.
An empty `firewallRules` means the tag adds nothing; the host's role and
other tags still apply. Human output shows the description, host count,
priority, and the rule table laid out like `role get`, with the same
allow-everything warning. It also warns when the server returns a different
tag than the one asked for, or when `firewallRulesCount` disagrees with the
rules listed. Use `--json` for config overrides and route subscriptions. Key
permission: `tags:read`.

### Delete a tag — `dn tag delete`

```bash
dn tag delete <KEY:VALUE> --yes --json
```

Returns `{ "name": "key:value", "deleted": true }`. Same `--yes` rule as
`host delete`. Key permission: `tags:delete`.

**You MUST confirm with the user before running this**, naming the tag and
how many hosts carry it (`hostCount` from `dn tag list --json`). The API
docs don't say what happens to hosts still carrying it or to rules that list
it in `allowedTags`, so treat traffic its rules or those rules allow as at
risk; a refusal comes back as an API error. One tag per call.

### List networks — `dn network list`

```bash
dn network list --json
```

Returns `{ "data": [ network… ], "metadata": { … } }`. Each network has `id`
(`network-…`), `name`, `description`, `cidrs` (the overlay prefixes — an IPv6
one and, on dual-stack networks, an IPv4 one), `hostCount`, `curve` (`25519`
or `P256`), `certVersion`, and two lighthouse settings that live on the
network, not on any host:

| field | meaning |
|-------|---------|
| `disableManagedLighthouses` | `false` means Defined's managed lighthouses back the network. They are not hosts, so `host list` never shows them — a network with no lighthouse host is still fine when this is `false`. |
| `lighthousesAsRelays` | `true` means the network's self-hosted lighthouses also act as relays. |

Use it to find the id for `host create --network`, and to answer "how do my
hosts find each other" or "do I have relays" — check these flags before
concluding anything from the hosts list alone.

### Show one network — `dn network get`

```bash
dn network get <NETWORK_ID> --json
```

Returns `{ "data": network, "metadata": {} }`: one network with the same
fields as a `network list` entry. Key permission: `networks:read`.

### Delete a network — `dn network delete`

```bash
dn network delete <NETWORK_ID> --yes --json
```

Returns `{ "id": "network-…", "deleted": true }`. Same `--yes` rule as
`host delete`. Key permission: `networks:delete`. The API refuses with
`ERR_HAS_DEPENDENTS` while the network still has hosts (`hostCount` above 0
in `dn network list --json`); delete those first, each with its own
confirmation.

**You MUST confirm with the user before running this**, naming the network.
One id per call.

### Read the audit log — `dn audit-log list`

```bash
dn audit-log list --json                                 # 500 most recent entries
dn audit-log list --target <ID> --json                   # one resource's history
dn audit-log list --target-type host --limit 50 --json   # one kind of resource
```

Returns one page of `{ "data": [ entry… ], "metadata": { … } }`, newest
first; `--cursor=<nextCursor>` goes further back. Each entry has
`timestamp`, `event.type` (`CREATED`, `UPDATED`, `DELETED`, `ENROLLED`, `RENEWED`, `BLOCKED_HOST`, …), `target`
(`{type, id}` — the resource acted on), `actor` (who did it: a `user`, an
SSO `oidcUser`, or an `endpointOIDCUser` — someone who enrolled a device by
signing in — with an `email`, an `apiKey` or `host` with an `id` and
`name`, or `support` / `system`), and `event.before` / `event.after`, the
resource's state either side of the change (shape varies by target; `null`
on a create or delete). Key permission: `audit-logs:list`.

Use it to answer "who deleted that host", "when did this role's rules
change", or "what has this API key done". Start with `--target` when the
question names a resource, so its history isn't spread across pages.
`ENROLLED` and `RENEWED` entries carry a host's whole config and CA
certificates (about 10 KB each), so a smaller `--limit` keeps output
manageable.

## Safety

| operation | gate |
|-----------|------|
| `host list`, `host get`, `host search`, `role list`, `role get`, `tag list`, `tag get`, `network list`, `network get`, `audit-log list` | free — reads change nothing |
| `host edit` | a write: renaming is cosmetic, but `--role`, `--clear-role`, `--add-tag`, and `--remove-tag` change the host's firewall. Confirm the host and the role or tag with the user first. |
| `host create` | a write: it creates a billable host and a one-time enrollment code. Confirm the name, the network, and any `--role` or `--tags` with the user first — like `host edit`, a role or tag sets the new host's firewall. |
| `host delete` | destructive and irreversible: the device loses network access, and getting it back means creating a new host and re-enrolling. Always get explicit user confirmation for the specific host. |
| `role delete`, `tag delete` | destructive and irreversible: the firewall rules go with it, which can change what traffic hosts that had it can receive. Always get explicit user confirmation for the specific role or tag. |
| `network delete` | destructive and irreversible, though the API refuses while the network has hosts. Always get explicit user confirmation for the specific network. |

## Where this is going (not built yet)

Role writes are still missing: `role create` / `role add-rule`. The
account's default role denies all inbound traffic, so nothing can reach a
host enrolled via `host create` until a role with firewall rules exists
and is assigned, or it carries a tag with firewall rules. `dn role list`
shows whether such a role already exists, and `host edit --role` assigns it; creating the role itself still happens in
the admin panel. Say so rather than promising two hosts will reach each other.
