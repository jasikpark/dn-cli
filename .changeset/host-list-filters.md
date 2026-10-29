---
default: minor
---

# Filter `host list` and `host search` server-side

`dn host list` and `dn host search` take the filters `GET /v2/hosts` offers:
`--role`, `--network`, `--tag` (repeatable), `--lighthouse`, `--relay`,
`--blocked`, `--update-available`, `--platform`, `--never-seen`, and
`--oidc-user`. The boolean flags accept `=false` to keep the opposite set, and
every flag ANDs with the others and with a search query. Ids and tags are
checked for shape before any request is made.
