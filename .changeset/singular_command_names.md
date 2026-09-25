---
default: minor
---

# Singular command names: `dn host`, `dn network`, `dn role`, `dn tag`

The top-level commands now use the singular noun, like `gh repo`: `dn host list`,
`dn network list`, `dn role get`, `dn tag get`. The plural names (`dn hosts`,
`dn networks`, `dn roles`, `dn tags`) still work as hidden aliases, so existing
scripts keep running. (#79)
