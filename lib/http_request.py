"""
http_request: one request head, parsed to the form the inspect listener emits.

`parse_request` splits the head (`http_framing`), reduces the target and
authority to the name policy matches (`http_target`) and decides the body's
framing. `rebuild_request` turns the result back into bytes: our framing and
the name we authorised, never the guest's head forwarded verbatim.
"""

from typing import NamedTuple

from http_framing import (
    _TOKEN_CHARS, Framing, RequestUnreadable, _get_all, _split_head,
    request_framing,
)
from http_target import SCHEME_HTTP, host_from_authority, normalise_target

class Request(NamedTuple):
    """One request head, parsed and normalised to the form we will emit."""

    method: str
    target: str        # always origin-form by the time this exists
    version: str
    authority: str     # what our Host header will say, port included
    host: str          # the normalised name the policy is matched against
    headers: tuple     # (name, value) as the guest wrote them
    framing: Framing
    expects_continue: bool
    wants_close: bool
    # The Upgrade value to re-emit; "" for an ordinary request.
    upgrade: str = ""

    @property
    def path(self) -> str:
        """The target's path without its query, which is what `paths` is
        matched against."""
        return self.target.partition("?")[0]


# Headers never forwarded: the hop-by-hop names, the framing headers and
# Host, which are re-emitted from what was computed and authorised.
#
# A fixed list, not the names the guest's own `Connection` header lists
# (RFC 9110 §7.6.1): honouring that would let the guest choose which of our
# headers survive. An extra name it lists is forwarded, and the origin
# ignores what it does not know.
_NOT_FORWARDED = frozenset((
    "host", "content-length", "transfer-encoding", "connection",
    "proxy-connection", "keep-alive", "te", "trailer", "upgrade", "expect",
))


# Upgrades not carried. h2c moves the connection onto frames this relay
# cannot read, which would end per-request authorisation.
_UPGRADE_REFUSED = frozenset(("h2", "h2c"))


def _upgrade_offer(headers, tokens, version):
    """The Upgrade value to forward, or "" for a request that is not one.

    "" also for an upgrade not carried, and for HTTP/1.0: the request then
    goes up as the ordinary request it also is, and the origin declines to
    switch, as RFC 9110 defines.
    """
    if version != "HTTP/1.1" or "upgrade" not in tokens:
        return ""
    offered = [v.strip() for v in _get_all(headers, "upgrade") if v.strip()]
    joined = ", ".join(offered)
    for entry in joined.split(","):
        name = entry.strip().split("/", 1)[0].strip().lower()
        if name in _UPGRADE_REFUSED:
            return ""
    return joined


def parse_request(head, scheme=SCHEME_HTTP):
    """A Request from a request head, normalised and framed, or raise."""
    start, headers = _split_head(head)
    parts = start.split(" ")
    if len(parts) != 3:
        raise RequestUnreadable(
            f"request line {start!r} is not three space-separated fields")
    method, target, version = parts
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        raise RequestUnreadable(f"{version!r} is not a version we relay")
    if not method or any(c not in _TOKEN_CHARS for c in method):
        raise RequestUnreadable(f"method {method!r} is not a token")
    target, authority = normalise_target(method, target, scheme)
    if authority is None:
        hosts = _get_all(headers, "host")
        if len(hosts) != 1:
            raise RequestUnreadable(
                f"{len(hosts)} Host headers: with no absolute-form authority "
                "there is exactly one name that could authorise this request")
        authority = hosts[0]
    # The port is either absent or this plane's, so the bare name is what
    # goes up.
    host = host_from_authority(authority.strip().lower(), scheme).host
    connection = ",".join(_get_all(headers, "connection")).lower()
    tokens = {t.strip() for t in connection.split(",")}
    wants_close = "close" in tokens or (
        version == "HTTP/1.0" and "keep-alive" not in tokens)
    expects = [v.strip().lower() for v in _get_all(headers, "expect")]
    if expects and expects != ["100-continue"]:
        raise RequestUnreadable(
            f"Expect {', '.join(expects)!r} is an expectation this relay "
            "cannot honour")
    return Request(
        method=method, target=target, version=version, authority=host,
        host=host, headers=headers, framing=request_framing(headers),
        expects_continue=bool(expects) and version == "HTTP/1.1",
        wants_close=wants_close,
        upgrade=_upgrade_offer(headers, tokens, version))


def rebuild_request(req):
    """The bytes sent upstream: our framing, and the name we authorised.

    Header names go up lowercased, as _split_head folded them. That is
    legal, and only an origin matching names case-sensitively notices.
    """
    lines = [f"{req.method} {req.target} {req.version}",
             f"Host: {req.authority}"]
    lines += [f"{name}: {value}" for name, value in req.headers
              if name not in _NOT_FORWARDED]
    if req.framing.kind == "length":
        lines.append(f"Content-Length: {req.framing.length}")
    elif req.framing.kind == "chunked":
        lines.append("Transfer-Encoding: chunked")
    # An upgrade offer is re-emitted from what _upgrade_offer accepted, or
    # no origin could ever answer 101.
    if req.upgrade:
        lines.append(f"Upgrade: {req.upgrade}")
        lines.append("Connection: upgrade")
    else:
        # The guest's own version goes up, and a 1.0 guest is not offered
        # keep-alive: speaking 1.1 for it invites a chunked response, which
        # is relayed to a client that may never have heard of chunked.
        lines.append("Connection: close" if req.version == "HTTP/1.0"
                     else "Connection: keep-alive")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
