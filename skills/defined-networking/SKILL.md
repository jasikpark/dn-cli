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

### Create a host — `dn hosts create`

```bash
dn hosts create --name <NAME> --json
```

Creates the host **and** its one-time enrollment code in a single call.

| flag | when to pass it |
|------|-----------------|
| `--name <NAME>` | required |
| `--network <id>` | only when the account has more than one network — otherwise auto-picked |
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
all traffic, so a freshly enrolled host is on the network but can't reach
anything yet.

### Delete a host — `dn hosts delete`

```bash
dn hosts delete <HOST_ID> --yes --json
```

Returns `{ "id": "host-…", "deleted": true }`. Without `--yes`, a `--json` run
fails with an error telling you to pass it — there is no prompt you can answer.

**You MUST confirm with the user before running this**, naming the host
(`dn hosts list --json` gives the id → name mapping). Never infer which host to
delete from context; one id per call.

## Safety

| operation | gate |
|-----------|------|
| `hosts list` | free — reads change nothing |
| `hosts create` | a write: it creates a billable host and a one-time enrollment code. Confirm the name and the network with the user first. |
| `hosts delete` | destructive and irreversible: the device loses network access, and getting it back means creating a new host and re-enrolling. Always get explicit user confirmation for the specific host. |

## Where this is going (not built yet)

Roles are still missing: `roles create` / `roles add-rule`. The account's
default role denies all traffic, so a host enrolled via `hosts create` is
"enrolled but mute" until a role with firewall rules exists and is assigned.
Until that ships, say so rather than promising two hosts will reach each
other.
