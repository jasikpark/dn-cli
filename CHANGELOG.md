# Changelog

All notable changes to this project are documented here.
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
