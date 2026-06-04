---
name: defined-networking
description: View and manage a Defined Networking (Nebula mesh VPN) network with the `dn` CLI. Use when the user asks about their Defined Networking or Nebula hosts, lighthouses, relays, network, or roles/tags — e.g. "list my hosts", "what's on my mesh network", "is my laptop online" — or (eventually) wants to add/set up/enroll a new device on their network.
---

# Defined Networking (`dn`) CLI

`dn` is a command-line client for the [Defined Networking](https://defined.net)
API — the managed [Nebula](https://github.com/slackhq/nebula) mesh VPN. Use it to
inspect and (later) manage the user's network.

## Prerequisite: the API key must be injected

`dn` reads `DEFINED_API_KEY` from the environment and never persists it. It is
injected per-invocation from 1Password — **`dn` does nothing without it.** Run
`dn` through `op run` with an env file that maps the key to a 1Password secret
reference:

```bash
op run --env-file=.env -- dn <args>     # from the dn-cli repo
```

If `dn` is installed on `PATH` and `DEFINED_API_KEY` is already available in the
environment, `dn <args>` works directly. If you see
`error: DEFINED_API_KEY is not set`, the secret isn't being injected — use the
`op run --env-file=.env` form (run it from the dn-cli repo so `.env` resolves).

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
op run --env-file=.env -- dn hosts list --json
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
