# dn-cli

An unofficial CLI (`dn`) for the [Defined Networking](https://defined.net) API.

**This is not an officially supported Defined Networking product.** Defined
Networking neither endorses nor supports it; report problems in this
repository's issues.

Rust + [clap](https://docs.rs/clap) + [ureq](https://docs.rs/ureq) (pure-Rust
TLS via rustls, so the binary statically links cleanly for per-platform npm
distribution later, à la `sentry-cli`).

Designed to be driven two ways:

- **Interactively** by a human (tables; confirmations on destructive actions)
- **Non-interactively** by an agent or script (`--json`, explicit flags, no prompts)

## Install

Prebuilt binaries for macOS (Apple Silicon and Intel), Linux (x64 and ARM64) and
Windows (x64) ship with every [release](https://github.com/jasikpark/dn-cli/releases).

Shell installer (macOS and Linux):

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/jasikpark/dn-cli/releases/latest/download/dn-cli-installer.sh | sh
```

With [cargo-binstall](https://github.com/cargo-bins/cargo-binstall), which fetches
the same prebuilt binary:

```bash
cargo binstall --git https://github.com/jasikpark/dn-cli dn-cli
```

Or build from source with a Rust toolchain:

```bash
cargo install --git https://github.com/jasikpark/dn-cli
```

## Auth

Log in once:

```bash
dn auth login
```

It points you at <https://admin.defined.net/settings/api-keys/add> to create a
key (pick only the permissions you need), asks for it with the input hidden,
verifies it against the API, and stores it in the **OS keyring**: macOS
Keychain, Windows Credential Manager, or the Secret Service (GNOME Keyring,
KWallet) on Linux. The profile itself — which API server, where the key is —
goes in `~/.config/dn/auth.json` (`%APPDATA%\dn\auth.json` on Windows; override
the directory with `DN_CONFIG_DIR`); the key never does.

To script it, pipe the key in with `--key-stdin`:

```bash
printf '%s' "$KEY" | dn auth login --key-stdin
```

**1Password instead:** `dn auth login --ref op://vault/item/field` stores a
1Password *secret reference*, and every `dn` call resolves it with
[`op read`](https://developer.1password.com/docs/cli/get-started/), so
1Password's unlock prompt gates each invocation.

On a headless Linux machine with no Secret Service (a server, a container), the
keyring is unavailable; use `--ref` or `DEFINED_API_KEY` there.

`dn auth status` shows which profile and key source are active; `dn auth logout`
forgets the profile and deletes its keyring entry.

### Profiles

Each login is stored as a named profile, one per Defined Networking account.
`auth login` without `--profile` saves to the default profile (`default` on a
fresh setup). Profile names are lowercase letters, digits, `-`, `_` and `.`.
Add more for other accounts:

```bash
dn auth login --profile work
dn host list --profile work           # or DN_PROFILE=work dn host list
dn auth list                          # * marks the default
dn auth switch work                   # make it the default
dn auth logout --profile work         # or --all
```

A call uses `--profile`, else `DN_PROFILE`, else the default profile. Like
`gh`, `auth login` makes the profile it saves the default (`--keep-default`
opts out), and logging out of the default makes another profile the default.
Each of these commands prints the resulting profiles.

Credentials from before profiles are converted the first time any `dn` command
runs, with a one-line notice on stderr: the old `auth.json` becomes a `default`
profile, and `config.json`'s `api_url` moves into it.

For CI or agents, `DEFINED_API_KEY` in the environment takes precedence over any
profile's key. It may hold the raw key or an `op://` reference — `dn` resolves
the latter the same way.

### Testing against another API server

Every profile talks to `https://api.defined.net` unless it was saved with
`--api-url`. That, and `DEFINED_API_URL` (which overrides any profile's URL for
one call), exist for testing — against a local mock API, or a non-production
server:

```bash
DEFINED_API_URL=http://127.0.0.1:8080 DEFINED_API_KEY=test dn host list   # a local mock
dn auth login --profile test --api-url https://api.test.example --keep-default
```

Plain `http://` is only allowed to this machine (`localhost`, `127.0.0.1`,
`[::1]`), so the key never crosses a network unencrypted. When a call isn't
going to `https://api.defined.net`, `dn` says so on stderr (never under
`--json`).

## Develop

With [`just`](https://github.com/casey/just):

```bash
just run host list --json
```

Or directly:

```bash
cargo run -- host list --json
cargo build --release
```

`just mutants` runs [cargo-mutants](https://mutants.rs/) over the crate: it edits
one expression at a time and reruns `cargo test`. A MISSED mutant is an edit the
suite did not notice, so it names a behaviour nothing asserts on.
`just mutants-diff` narrows that to the lines the current change touches.
The `cargo-mutants` skill in `.claude/skills/` loads when Claude Code runs in this
checkout and walks through a run and the survivor triage.

### Changelog and releases

`CHANGELOG.md` is generated from commit subjects, so every user-visible change
needs a [conventional commit](https://www.conventionalcommits.org/): `feat:`
and `fix:` become entries under the next version, `feat!:` (or a
`BREAKING CHANGE:` footer) marks a breaking change, and other types (`docs:`,
`chore:`, `test:`) stay out of the changelog. Write the subject as the line a
user should read in the release notes. The `Require changes to be documented`
check on each PR is [Knope](https://knope.tech) looking for exactly that.

On every push to `main`, Knope opens or updates a `chore: prepare release X`
PR that bumps `Cargo.toml` and writes `CHANGELOG.md`. Merging it pushes the
`vX` tag, and cargo-dist builds the binaries and publishes the release.

## Claude Code plugin

This repo doubles as a [Claude Code](https://claude.com/claude-code) plugin
(`.claude-plugin/plugin.json`). The `defined-networking` skill
(`skills/defined-networking/SKILL.md`) teaches Claude to drive `dn` — checking
`dn auth status --json` first and parsing `--json` output. The repo is also a
one-plugin marketplace, so install it with:

```bash
claude plugin marketplace add jasikpark/dn-cli
claude plugin install dn-cli@dn-cli
```

For local development, `claude --plugin-dir /path/to/dn-cli` loads the checkout
for one session. The longer-term goal: *"I have this device, set it up on my
network"* — conversational device enrollment.

## Status

- Reads: `host list`, `host search <QUERY>` — the latter wraps the
  `GET /v2/hosts?filter.search=` query, a server-side match across each host's
  name, IP addresses, assigned role name, and tags (the same surface the admin
  panel's search box drives). The query must be at least two characters. Key
  permission: `hosts:list`. (`filter.search` is not in the public OpenAPI spec
  yet, so it's pinned to the web client's observed behaviour.)
- Auth: `auth login` / `auth status` / `auth list` / `auth switch` /
  `auth logout` — named profiles in `~/.config/dn/auth.json`, each with its key
  in the OS keyring or a 1Password secret reference resolved per call with
  `op read`. `--profile` / `DN_PROFILE` picks one per call.
- Writes: `host create` (host / lighthouse / relay) — wraps the
  `POST /v2/host-and-enrollment-code` one-shot endpoint, so the OTP comes
  back in the same response and the human view prints the `dnclient enroll`
  command to copy. Network is auto-picked when the account has exactly one.
  Hosts get an IPv4 whenever the network has an IPv4 prefix — the API alone
  leaves dual-stack hosts v6-only — and `--no-ipv4` skips that for a v6-only
  host. Key permissions: `hosts:create`, `hosts:enroll`, and `networks:list`
  (auto-pick) or `networks:read` (`--network <id>`).
- Deletes: `host delete <HOST_ID>` — wraps `DELETE /v1/hosts/{id}`. An
  interactive run looks the host up first (`hosts:read`) and asks
  `Delete host "<name>" (<id>; <ips>)? [y/N]`; `--yes` skips the lookup and the
  prompt, and is required with `--json` or when stdin isn't a terminal. Key
  permission: `hosts:delete`.
- Edits: `host edit <HOST_ID>` — `--name`, `--role <ROLE_ID>` / `--clear-role`,
  `--add-tag`, `--remove-tag` (repeatable). Reads the host, applies the changes, and PUTs
  the whole object back via `/v3/hosts/{id}`; a no-op edit skips the write.
  Key permissions: `hosts:read` and `hosts:update`.
- Roles: `role list` — id, name, rule and host counts. Pair it with
  `host edit --role` to move a host off the default deny-all role.
  `role get <ROLE_ID>` shows one role's inbound firewall rules — allowed
  hosts, protocol, ports — in the admin panel's order. Key permission:
  `roles:read`, plus `roles:list` to show role names in rules instead of
  ids.
- Tags: `tag list` — name, rule and host counts, description, priority,
  highest priority first like the admin panel. Key permission: `tags:list`.
  `tag get <KEY:VALUE>` shows the inbound firewall rules a tag adds to every
  host carrying it, laid out like `role get`. Key permission: `tags:read`,
  plus `roles:list` for role names.
- Networks: `network list` — id, name, CIDRs, host count, whether managed
  lighthouses and lighthouses-as-relays are on, curve and cert version. The
  lighthouse settings live on the network, so this is where to look when the
  hosts list shows no lighthouse. Key permission: `networks:list`.
- Coming next: `role create` and `role add-rule` — the default role denies
  all traffic, so newly enrolled hosts share a network but can't talk to
  each other until a permissive role exists and is assigned.

## Prior art

- [quickvm/defined-mcp](https://github.com/quickvm/defined-mcp) — Python/`uv`
  MCP server with broad hosts, roles, tags, networks, and routes coverage, plus
  a `network-architect` Claude skill for auditing and firewall policy design.
- [geoffbelknap/defined-mcp](https://github.com/geoffbelknap/defined-mcp) —
  TypeScript MCP server published as `@defined-net/mcp-server`, with dry-run
  previews on mutating tools, MCP resources and prompts, and `debug-host`.

## License

[FSL-1.1-Apache-2.0](./LICENSE.md) — source-available; converts to Apache-2.0
two years after each release. Provided as is, without warranty of any kind.
