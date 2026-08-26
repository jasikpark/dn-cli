---
name: defined-networking
description: View and manage a Defined Networking (Nebula mesh VPN) network with the `dn` CLI. Use when the user asks about their Defined Networking or Nebula hosts, lighthouses, relays, network, or roles/tags — e.g. "list my hosts", "what's on my mesh network", "is my laptop online" — or (eventually) wants to add/set up/enroll a new device on their network.
---

# Defined Networking (`dn`) CLI

`dn` is a command-line client for the [Defined Networking](https://defined.net)
API — the managed [Nebula](https://github.com/slackhq/nebula) mesh VPN. Use it to
inspect and (later) manage the user's network.

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

## Safety

`dn` is **read-only today** — it can only list. There is nothing here that can
modify the network. Write and destructive operations (enrolling devices,
blocking, deleting) are a deliberate later phase and will be gated behind
explicit confirmation when they land.

## Where this is going (not built yet)

The end goal is to make device setup conversational: *"I have this device, set it
up on my network."* That will mean creating a host + an enrollment code and
returning the steps to enroll the device. Until that ships, this skill covers
reads only — don't promise enrollment yet.
