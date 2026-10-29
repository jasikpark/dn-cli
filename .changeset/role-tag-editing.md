---
default: minor
---

# Create and edit roles and tags

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
