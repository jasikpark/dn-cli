---
default: patch
---

# Don't send plain-HTTP loopback requests through a proxy

With `ALL_PROXY`, `HTTPS_PROXY` or `HTTP_PROXY` set and no `NO_PROXY` entry for
localhost, a call to an `http://localhost` API URL went to the proxy, API key
included. `dn` now ignores proxy settings for `http://` URLs, which it only
allows to this machine.
