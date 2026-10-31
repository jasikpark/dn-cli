---
default: minor
---

# Block, unblock, and re-enroll hosts

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
