"""What a hut's policy and request filters do with one host, and with one
request to it, decided by the inspector's own parser and Policy methods."""

from moatery.http_framing import RequestUnreadable
from moatery.http_request import parse_request
from moatery.http_target import SCHEME_HTTP, SCHEME_HTTPS
from moatery.inspect_document import (hostname_match, path_readings,
                                      policy_governs)
from moatery.request_filter import FILTER_BODY_MAX


def _any(values):
    if values is None or "*" in values:
        return "any"
    return ", ".join(values) or "none"


def _judge(policy, host, method, path, scheme):
    """(the path `paths` is matched against or None, the verdict) for one
    request on one plane, in the order the inspector asks."""
    if not policy.admits(host):
        return None, "refused, 403: the host is not admitted"
    head = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    try:
        req = parse_request(head, scheme)
    except RequestUnreadable as exc:
        return None, f"refused, 400: {exc}"
    if not policy.permits(req.host, req.method, req.path):
        return req.path, "refused, 403"
    run = policy.request_filters.filter_for(req.host)
    if run is None:
        return req.path, "permitted"
    return req.path, (f"permitted, then a body goes through {run}, which "
                      "may refuse or rewrite it")


def report(policy, host, method=None, path=None, *, credential_error=None):
    """The report's lines. `host` is a normalised name; a request is
    judged when `method` or `path` is given, GET and / standing in for
    the one not. `credential_error` says why the credential the host is
    brokered with cannot be read, if it cannot."""
    hosts = [p for p in policy.hosts if hostname_match(host, (p,))]
    splice = [p for p in policy.splice if hostname_match(host, (p,))]
    internal = [p for p in policy.internal_expected
                if hostname_match(host, (p,))]
    governing = policy_governs(host, policy.policy)
    spliced = policy.splices(host)
    lines = [host]
    if hosts:
        lines.append(f"  admitted    by hosts: {', '.join(hosts)}"
                     + ("; its entries alone decide its requests"
                        if governing else ""))
    elif governing:
        lines.append("  admitted    by its entries; hosts does not name it")
    else:
        lines.append("  admitted    no: neither hosts nor an entry names it"
                     + (f"; splice's {', '.join(splice)} admits nothing"
                        if splice else ""))
    if policy.admits(host):
        if spliced:
            by = ('the document\'s tls is "splice"' if policy.tls == "splice"
                  else ", ".join(splice))
            lines.append(f"  tls         spliced, by: {by}")
            lines.append("              over https it is checked by name "
                         "alone, and a ClientHello carrying ECH")
            lines.append("              (a browser's GREASE included) is "
                         "refused; over http its requests are read")
        else:
            lines.append("  tls         terminated, its requests read")
        if governing:
            lines.append(f"  entries     {len(governing)} govern"
                         f"{'s' if len(governing) == 1 else ''} it, and a "
                         "request passes if any one permits it:")
            width = max(len(e.host) for e in governing)
            for e in governing:
                lines.append(f"                {e.host:<{width}}  methods: "
                             f"{_any(e.methods)}  paths: {_any(e.paths)}"
                             + (f"  credential: {e.credential}"
                                if e.credential else ""))
        else:
            lines.append("  entries     none: any method, any path")
        credential = policy.credential_for(host)
        if not credential:
            lines.append("  credential  none")
        elif credential_error:
            lines.append(f"  credential  {credential}, which the broker "
                         f"cannot attach: {credential_error}")
        else:
            lines.append(f"  credential  {credential}, which the broker "
                         "attaches")
        run = policy.request_filters.filter_for(host)
        if run is None:
            lines.append("  filter      none")
        else:
            lines.append(f"  filter      {run}, on each request with a body"
                         + (" over http; https is spliced" if spliced
                            else ""))
            lines.append(f"              a body over {FILTER_BODY_MAX >> 20} "
                         "MiB, a Content-Encoding or an Upgrade is "
                         "refused unread")
    if internal:
        lines.append(f"  internal    expected in private space, by: "
                     f"{', '.join(internal)}")
    if method is not None or path is not None:
        method, path = method or "GET", path or "/"
        # A spliced host's requests are read on the cleartext plane alone.
        matched, verdict = _judge(policy, host, method, path,
                                  SCHEME_HTTP if spliced else SCHEME_HTTPS)
        said = f"{method} {path}"
        readings = path_readings(matched) if matched is not None else ()
        if readings and readings != (path,):
            said += f" (matched as {' and as '.join(readings)})"
        if not spliced or not policy.admits(host):
            lines.append(f"  request     {said}: {verdict}")
        else:
            lines.append(f"  request     {said}")
            lines.append("              over https: not read, the "
                         "connection is spliced")
            lines.append(f"              over http: {verdict}")
    return lines
