# dn-cli

An unofficial CLI (`dn`) for the [Defined Networking](https://defined.net) API.

**This is not an officially supported Defined Networking product.** Defined
Networking neither endorses nor supports it; report problems in this
repository's issues.

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

This reads the version from `main`, so it fails in the gap between a version bump
landing and its release being published; use the installer above meanwhile.

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

## Contributing

For local development, checks, test-server configuration, and release
conventions, see [CONTRIBUTE.md](./CONTRIBUTE.md).

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
