# Changelog

All notable changes to this project are documented here.
## 0.4.8 (2026-11-05)

### Features

#### Debug a host's tunnels with dn host debug

`dn host debug` runs dnclient's debug commands on an online host through the
API's host command operation: `tunnel` and `cert` show what a host knows about
a peer, `lighthouse` shows a lighthouse's host map as the host sees it,
`create-tunnel` starts a handshake, and `stack` prints a stack trace. Each takes
the host's id and, except `stack`, a Nebula IP. The API key needs the
`hosts:debug` permission.

#### Stream a host's logs with dn host debug logs

`dn host debug logs <host id>` streams the host's dnclient logs for
`--duration` (default 1m, at most 10m) at `--level` (default `info`), printing
each line as it arrives. Under `--json` it prints one JSON object per line
(NDJSON) rather than a single document. The host streams for the whole
duration even if `dn` is stopped early, and reloads its Nebula config when the
session starts and ends. The API key needs the `hosts:debug` permission.

## 0.4.7 (2026-11-03)

### Features

#### Wait for a host to check in with `dn host wait`

`dn host wait <host id>` polls a host until it has checked in with Defined
Networking, then shows it: the end of setting up a device with `dn host create`
and `dnclient enroll`. `--timeout` (default 10m) and `--interval` (default 5s)
take durations like `90s` or `1h`; `--since now` waits for a fresh check-in
when re-enrolling a host that was seen before. A wait that runs out of time
exits 1 with `ERR_TIMEOUT` under `--json`.

### Fixes

- stop list walks that loop between cursors (#172)

#### Credentials from before profiles are no longer converted

`dn` used to convert an `auth.json` without a `version` (the single-reference
layout from before 0.2.10) into a `default` profile on every call, and move
`config.json`'s `api_url` into it. Both conversions are gone. Such an
`auth.json` now reads as invalid, with a message to run `dn auth login`, which
replaces it; `config.json` is ignored. If you still have either file, log in
again, passing `--api-url` if you used a non-production API.

## 0.4.6 (2026-11-02)

### Features

#### Create, list, edit, and revoke join keys

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

## 0.4.5 (2026-10-31)

### Features

#### Block, unblock, and re-enroll hosts

`dn host block` cuts a host off from the rest of the network without deleting
it, and `dn host unblock` lets it back in. `--json` prints the updated host;
the human view confirms the new state (block also prints the command that
undoes it) and fails if the response doesn't confirm it.

`dn host enroll-code` issues a new one-time enrollment code for a host that
already exists, for re-enrolling a reinstalled device. `--code-lifetime` sets
how long it lasts (60 seconds to 7 days, checked before the request is sent).

`dn host enroll-code` and `dn host create` now only print a
`dnclient enroll <code>` line when the code looks like one the API issues, so
a broken or hostile response can't put anything else into a command you paste
into a shell.

### Fixes

- correct stale and version-mangled lines in the defined-networking skill (#161)

## 0.4.4 (2026-10-29)

### Features

- list and show routes (#156)

### Fixes

- accept any platform value and shape-check the host id filters (#160)

## 0.4.3 (2026-10-29)

### Features

#### Create and edit roles and tags

`dn role create` and `dn role edit` manage a role's description and inbound
firewall rules; `dn tag create` and `dn tag edit` manage a tag's description,
firewall rules, route subscriptions, and place in the priority order
(`--before` / `--after`). Rules are given as
`PROTO[/PORTS][,from=ROLE_ID][,tag=a:b]...[,desc=TEXT]` on `--rule`,
`--add-rule`, and `--remove-rule`, and are checked locally before any request.

A role edit reads the role and writes the whole thing back with the changes
applied, since the API's role update replaces every field. A tag edit sends
only the fields that change through the API's partial update, so config
overrides are never touched. An edit that changes nothing makes no write.
Roles can't be renamed: the API has no field for it.

## 0.4.2 (2026-10-29)

### Features

#### Filter `host list` and `host search` server-side

`dn host list` and `dn host search` take the filters `GET /v2/hosts` offers:
`--role`, `--network`, `--tag` (repeatable), `--lighthouse`, `--relay`,
`--blocked`, `--update-available`, `--platform`, `--never-seen`, and
`--oidc-user`. The boolean flags accept `=false` to keep the opposite set, and
every flag ANDs with the others and with a search query. Ids and tags are
checked for shape before any request is made.

## 0.4.1 (2026-10-13)

### Fixes

- verify login credentials without requiring host permissions (#139)

## 0.4.0 (2026-10-12)

### Breaking Changes

#### `dn auth status` names the organization and key

`auth status` now asks the API who the key belongs to and shows the organization (with its plan) and the key's name, so a wrong-account key shows up before you run anything against it. `--json` output gains an `owner` object, and an `owner_error` envelope when the lookup fails. If the lookup fails (a rejected key, a failed `op read`, an unreachable API), `auth status` still reports the local setup, then exits 1. `--offline` restores the previous behavior: no API call and no 1Password prompt. Scripts that only need the local setup, or that run where the API or 1Password is unavailable, should pass it.

### Features

- name the resource when deleting with --yes (#124)
- show the organization and key in auth status (#128)

#### `delete --yes` names what it deleted

`dn host delete`, `dn role delete`, and `dn network delete` with `--yes` now look the resource up first, so the result reads `Deleted host "Build Server" (host-…)` instead of the bare id. The lookup is best-effort: a key without the read scope still deletes, and the result names the id alone. `--json` output is unchanged and makes no lookup.

### Fixes

#### Dependency updates no longer need a changeset

Renovate PRs carry the `renovate` label, which Knope Bot's changeset check skips; dependency updates ship with the next release without a changelog entry of their own.

## 0.3.0 (2026-10-07)

### Breaking Changes

#### Lists return one page at a time

`host list`, `host search`, `role list`, `tag list`, and `network list` used to walk every page and print the whole set. Each now fetches one page of up to 500 items, matching the admin panel. Pass `--limit` (alias `--page-size`) for a smaller page and `--cursor` for the next one. Without `--json`, stderr prints the command for the next and previous page. With `--json`, `metadata.hasNextPage` and `metadata.nextCursor` say whether more remain. A script that read the full list from one call should follow `nextCursor` until `hasNextPage` is false.

### Features

- add `dn audit-log list` and page every list with `--cursor` (#110)

## 0.2.14 (2026-10-07)

### Features

- add `dn host get` and `dn network get` (#105)

## 0.2.13 (2026-10-03)

### Features

- add `dn role delete`, `dn tag delete`, and `dn network delete` (#102)

## 0.2.12 (2026-10-01)

### Fixes

- stop cargo-binstall falling back to crates.io (#94)

## 0.2.11 (2026-10-01)

### Features

- store API keys in the OS keyring by default (#91)
- identify requests with a dn-cli User-Agent (#93)

## 0.2.10 (2026-09-30)

### Features

- report every --json error in the API's error envelope (#87)
- named profiles for multiple accounts (#89)

## 0.2.9 (2026-09-29)

### Features

- add `dn tag list` (#85)

## 0.2.8 (2026-09-29)

### Features

#### Singular command names: `dn host`, `dn network`, `dn role`, `dn tag`

The top-level commands now use the singular noun, like `gh repo`: `dn host list`,
`dn network list`, `dn role get`, `dn tag get`. The plural names (`dn hosts`,
`dn networks`, `dn roles`, `dn tags`) still work as hidden aliases, so existing
scripts keep running. (#79)

### Fixes

- keep the API's key order in --json output (#84)

## 0.2.7 (2026-09-25)

### Features

- dn tags get (#76)

### Fixes

- version the plugin manifests with each release (#77)

## 0.2.6 (2026-09-23)

### Features

- dn roles get (#72)

## 0.2.5 (2026-09-20)

### Features

- dn hosts search (#66)

## 0.2.4 (2026-09-10)

### Features

- dn networks list (#52)

### Fixes

- count VS16 emoji as one column, like most terminals do (#53)

## 0.2.3 (2026-09-09)

### Fixes

- use environment credentials even when auth.json is malformed (#42)

## 0.2.2 (2026-09-04)

### Features

- assign a role with dn hosts edit --role (#40)

## 0.2.1 (2026-09-01)

### Features

- dn hosts edit with --name, --add-tag, --remove-tag
- split config into settings (config.json) and credentials (auth.json)
- add dn roles list with paginated table output (#34)
- retry rate-limited requests with exponential backoff (#37)

### Fixes

- harden hosts edit after adversarial review
- defense-in-depth from final roast
- canonicalize auth path on logout to match write_private symlink contract
- sanitize control characters in human-mode output (#35)

## 0.2.0 (2026-08-26)

### Breaking Changes

- take the host name as a positional argument

### Features

- dn hosts delete with a confirmation gate

## 0.1.3 (2026-08-26)

### Features

- create host / lighthouse / relay + enrollment in one shot
- assign IPv4 by default on networks with an IPv4 prefix

### Fixes

- clearer --network permission error and --no-ipv4 help

## 0.1.2 (2026-08-26)

### Features

- dn auth login / status / logout backed by 1Password references

### Fixes

- harden login verify, config I/O, and status reporting
- accept the quoted reference 1Password copies for spaced item names
- reject unsupported name characters in a reference before calling op
- make config writes race-safe and surface op diagnostics under --json

## 0.1.1 (2026-06-04)

### Features

- dn-cli reads-only tracer
- surface Defined API error bodies on non-2xx
- emit structured JSON error envelope in --json mode
- follow cursor pagination on list, add unit tests
- switch list to v2 endpoint (dual-stack ipAddresses)
- make op run secret injection work + clearer setup
- aligned table output for human host list
- add Claude Code skill for the dn CLI
- scaffold cargo-dist for npm distribution
- add shell installer alongside npm
- add knope prepare-release PR flow

### Fixes

- read nextCursor as documented pagination field
