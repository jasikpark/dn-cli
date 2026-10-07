# Changelog

All notable changes to this project are documented here.
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
