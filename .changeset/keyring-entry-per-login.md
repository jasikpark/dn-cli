---
default: patch
---

# Keep each config directory's keyring keys apart

Keyring entries were named after the profile alone, so two config directories
(`DN_CONFIG_DIR`, or a changed `XDG_CONFIG_HOME`) with a profile of the same
name shared one key: logging in to one silently pointed the other at that
organization, and logging out of one broke the other. A logout running at the
same moment as a login to the same profile could also delete the key that
login had just stored.

Each `dn auth login` now stores its key in an entry of its own, named
`<profile>/<random id>`, and `auth.json` records which one. Profiles saved by
an earlier `dn` keep working and move to an entry of their own the next time
you log in to them. A `dn` older than this one can't read a profile saved by
this one; log in again after a downgrade.
