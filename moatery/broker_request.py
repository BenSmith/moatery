"""What leaves this host carrying a credential, decided without a socket.

The broker's request path as free functions, so it can be tested without a
server: which of a caller's headers go upstream, how a request is framed
before any of it is forwarded, and how a response is re-framed on the way
back.

Used by `libexec/moat-broker`.
"""

# Headers that are meaningful only for a single transport hop and must never be
# copied across one (RFC 9110 §7.6.1).
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})

# A caller's own credential headers are dropped, so the broker cannot relay
# a key the guest found. The configured auth header is stripped by name as
# well, in forwarded_headers.
STRIP_FROM_REQUEST = frozenset({
    "authorization", "x-api-key", "api-key", "x-goog-api-key",
    "cookie", "host", "content-length",
})

# Dropped from a relayed response: the hop-by-hop set, and Content-Length,
# which this hop re-frames. Date and Server pass through, so a brokered host
# looks like every other.
DROP_FROM_RESPONSE = HOP_BY_HOP | {"content-length"}

# The largest request body read, in bytes.
MAX_REQUEST_BYTES = 64 * 1024 * 1024


def forwarded_headers(incoming, profile):
    """The headers to send upstream, given the ones the caller sent.

    Compared lowercased: the dict keeps the caller's spelling, so a caller's
    `x-custom-key` would otherwise go up beside our `X-Custom-Key`.
    """
    strip = STRIP_FROM_REQUEST | HOP_BY_HOP | {profile.auth_header.lower()}
    headers = {k: v for k, v in incoming.items() if k.lower() not in strip}
    headers[profile.auth_header] = profile.auth_value
    headers["Host"] = profile.host
    return headers


def request_framing(path, headers):
    """(body length, rejection) for a request, before any of it is forwarded.

    A rejection is (status, log reason, client message); None means proceed.
    Each closes the connection, since the body is unread. A chunked body is
    refused: Transfer-Encoding is stripped as hop-by-hop, and without the
    refusal the request would go up with its body silently dropped.
    """
    if not path.startswith("/"):
        # An absolute-form target asks a proxy to choose the destination.
        return 0, (400, "absolute-target",
                   "absolute request targets are not accepted\n")

    if headers.get("Transfer-Encoding"):
        return 0, (411, "chunked-request",
                   "chunked request bodies are not accepted; send "
                   "Content-Length\n")

    declared = headers.get_all("Content-Length") or []
    if len(declared) > 1:
        # Two lengths frame two messages (RFC 9112 §6.3).
        return 0, (400, "duplicate-content-length",
                   "Content-Length appears more than once\n")

    raw = declared[0] if declared else None
    if raw is None or raw.strip() == "":
        return 0, None
    raw = raw.strip(" \t")
    # ASCII digits only, RFC 9110 §8.6. int() also takes a sign, `1_000` and
    # non-ASCII digits, and rfile.read(-1) reads to EOF.
    if not (raw.isascii() and raw.isdigit()):
        return 0, (400, "bad-content-length",
                   "Content-Length is not a number\n")
    length = int(raw)
    if length > MAX_REQUEST_BYTES:
        return length, (413, "body-too-large", "request body too large\n")
    return length, None


def response_framing(status, headers, method="GET"):
    """(headers to pass back, declared length, whether a body is forbidden).

    A HEAD response's Content-Length describes a body that never follows,
    and framing one would put bytes on the wire read as the next response.
    """
    passthrough = [(k, v) for k, v in headers
                   if k.lower() not in DROP_FROM_RESPONSE]
    # A Transfer-Encoding overrides a Content-Length (RFC 9112 §6.3), and
    # http.client decodes by the encoding, so the length is not declared.
    chunked = any(k.lower() == "transfer-encoding" for k, _ in headers)
    declared = None if chunked else next(
        (v for k, v in headers if k.lower() == "content-length"), None)
    return passthrough, declared, (status in (204, 304)
                                   or method == "HEAD")
