---
default: minor
---

# Debug a host's tunnels with dn host debug

`dn host debug` runs dnclient's debug commands on an online host through the
API's host command operation: `tunnel` and `cert` show what a host knows about
a peer, `lighthouse` shows a lighthouse's host map as the host sees it,
`create-tunnel` starts a handshake, and `stack` prints a stack trace. Each takes
the host's id and, except `stack`, a Nebula IP. The API key needs the
`hosts:debug` permission.
