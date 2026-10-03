"""
http_target: what a request target and an authority name, in one canonical
form.

The path is normalised here -- unreserved escapes decoded, dot segments
resolved, duplicate slashes collapsed -- and the normalised form is what the
policy matches and what goes upstream, so the two cannot address different
resources. A path with two readings among origins is refused instead. The
authority (`Host`, or an absolute-form target) and a redirect's `Location`
are reduced the same way to the one name policy is matched against.
"""

import ipaddress
from typing import NamedTuple

from .inspect_document import hostname_bad_character, normalize_hostname
from .egress_plane import CLEARTEXT, TLS
from .http_framing import RequestUnreadable

class Scheme(NamedTuple):
    """Which plane a request is read on: the absolute-form scheme it
    accepts, and the one port an authority may name."""

    name: str
    port: int


SCHEME_HTTP = Scheme("http", CLEARTEXT.guest_port)
SCHEME_HTTPS = Scheme("https", TLS.guest_port)


# RFC 3986's unreserved characters, whose escapes are equivalent to them.
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

_HEX = frozenset("0123456789abcdefABCDEF")


def _decode_unreserved(path):
    """A path with unreserved percent-encodings decoded and the rest kept.

    `%2e` is decoded, so dot-segment resolution sees the dots an origin
    will. An encoded slash is refused: origins split on whether it is a
    separator. Every other escape stays, in uppercase hex, so one path has
    one spelling.
    """
    out = []
    i = 0
    while i < len(path):
        ch = path[i]
        if ch != "%":
            out.append(ch)
            i += 1
            continue
        digits = path[i + 1:i + 3]
        if len(digits) != 2 or digits[0] not in _HEX or digits[1] not in _HEX:
            raise RequestUnreadable(
                f"{path[i:i + 3]!r} in the request target is not a percent "
                "escape, and a target with a stray % in it is read one way "
                "here and another by anything that repairs it")
        value = int(digits, 16)
        decoded = chr(value)
        if decoded == "/":
            raise RequestUnreadable(
                "an encoded slash in the request target: whether it separates "
                "two segments or sits inside one is a question origins answer "
                "differently, so it is not a path this can authorise")
        if decoded in _UNRESERVED:
            out.append(decoded)
        else:
            out.append("%" + digits.upper())
        i += 3
    return "".join(out)


def _resolve_dot_segments(path):
    """A path with `.` and `..` resolved and empty segments collapsed.

    A `..` at the root is discarded, as RFC 3986 says. A trailing slash is
    kept, since `/a` and `/a/` are different resources.
    """
    segments = path.split("/")
    trailing = segments[-1] in ("", ".", "..")
    out = []
    for segment in segments:
        if segment in ("", "."):
            continue                    # collapses `//` in the same pass
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    return "/" + "/".join(out) + ("/" if trailing and out else "")


def normalise_path(path):
    """The canonical form of an origin-form path, or raise.

    The query is carried through untouched and is not part of what `paths`
    matches. `;params` stay inside their segment, except on a dot segment,
    which _refuse_second_readings refuses.
    """
    if "#" in path:
        raise RequestUnreadable(
            "a fragment in the request target: it is not part of what is sent "
            "to an origin, and a parser that keeps it addresses a different "
            "resource from one that drops it")
    path, sep, query = path.partition("?")
    path = _decode_unreserved(path)
    _refuse_second_readings(path)
    return _resolve_dot_segments(path) + sep + query


def _refuse_second_readings(path):
    """Refuse a decoded path some origins read as another path.

    A backslash is a separator to some origins, and a dot segment with
    `;params` is a dot segment to those that strip params first:
    `/allowed/..;/admin` matches `/allowed/*` and reaches `/admin` there.
    """
    if "\\" in path or "%5C" in path:
        raise RequestUnreadable(
            "a backslash in the request target: some origins read it as a "
            "separator and some as a byte, so it is not a path this can "
            "authorise")
    for segment in path.split("/"):
        # `%3B` too, for an origin that decodes before it strips params.
        name, semi, _params = segment.replace("%3B", ";").partition(";")
        if semi and name in (".", ".."):
            raise RequestUnreadable(
                f"the segment {segment!r} is a dot segment to an origin that "
                "strips ;params and a name to one that does not, so it is "
                "not a path this can authorise")


def normalise_target(method, target, scheme=SCHEME_HTTP):
    """(origin-form target, authority or None) for a request target, or raise.

    An absolute-form target is rewritten to origin-form, and its authority
    becomes the name authorised; the Host header is then ignored, as RFC
    9110 §7.2 says.
    """
    if method == "CONNECT":
        raise RequestUnreadable(
            "CONNECT on the cleartext plane: this listener is transparent, so "
            "a guest reaching it believes it is talking to an origin and has "
            "no proxy to tunnel through")
    if target.startswith("/"):
        return normalise_path(target), None
    if target == "*":
        raise RequestUnreadable(
            "an asterisk-form target names no resource to authorise")
    got, sep, rest = target.partition("://")
    if not sep or got.lower() != scheme.name:
        raise RequestUnreadable(
            f"request target {target!r} is neither origin-form nor an "
            f"{scheme.name} absolute-form URI")
    # The authority ends at the first `/`, `?` or `#`: a query can carry a
    # slash of its own.
    cut = min((i for i in (rest.find("/"), rest.find("?"), rest.find("#"))
               if i != -1), default=-1)
    if cut == -1:
        authority, path = rest, "/"
    elif rest[cut] == "/":
        authority, path = rest[:cut], rest[cut:]
    else:
        authority, path = rest[:cut], "/" + rest[cut:]
    if "@" in authority:
        raise RequestUnreadable(
            "userinfo in the request target: parsers disagree about where the "
            "host in it begins, which is the whole of its use here")
    if not authority:
        raise RequestUnreadable("an absolute-form target with no authority")
    return normalise_path(path), authority


class Authority(NamedTuple):
    """An authority split into the name policy matches and the port it
    named."""

    host: str
    port: str          # "" when the authority carried none


def host_from_authority(authority, scheme=SCHEME_HTTP):
    """The name and port in an authority, or raise."""
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise RequestUnreadable(
                f"authority {authority!r} opens a bracketed literal and never "
                "closes it")
        host, rest = authority[:end + 1], authority[end + 1:]
        if rest and not rest.startswith(":"):
            raise RequestUnreadable(
                f"authority {authority!r} has trailing bytes after its "
                "bracketed literal")
        port = rest[1:]
    elif authority.count(":") > 1:
        raise RequestUnreadable(
            f"authority {authority!r} has several colons and no brackets, so "
            "where its port begins is a guess")
    else:
        host, _, port = authority.partition(":")
    host = normalize_hostname(host)
    if not host:
        raise RequestUnreadable(f"authority {authority!r} names no host")
    if host.startswith("["):
        # An IPv6 address and nothing else, and no scope id: `%` carries
        # whatever follows it.
        try:
            if "%" in host:
                raise ValueError(host)
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise RequestUnreadable(
                "the authority's bracketed literal is not an IPv6 "
                "address") from None
    else:
        ch = hostname_bad_character(host)
        if ch is not None:
            raise RequestUnreadable(
                f"the authority carries {ch!r}, which no host name is "
                "spelled with")
    # A plane only ever dials its own port, so an authority naming another
    # describes a destination neither end is on.
    if port not in ("", str(scheme.port)):
        raise RequestUnreadable(
            f"authority {authority!r} names port {port!r}, but this plane "
            f"only ever reaches port {scheme.port}")
    return Authority(host, port)


def redirect_target(location, scheme=SCHEME_HTTP):
    """(host, path) a Location header names, or (None, None) for neither.

    Only a log line is built on this, so a relative Location, or one that
    cannot be read, is (None, None) rather than a refusal. Any scheme is
    read. The path is normalised by normalise_path, so the note predicting
    a refusal matches the path the next request will be judged on; one that
    cannot be normalised is None.
    """
    text = location.strip()
    got, sep, rest = text.partition("://")
    if not sep or not got or "/" in got:
        return None, None
    cut = min((i for i in (rest.find("/"), rest.find("?"), rest.find("#"))
               if i != -1), default=-1)
    if cut == -1:
        authority, path = rest, "/"
    elif rest[cut] == "/":
        authority, path = rest[:cut], rest[cut:]
    else:
        authority, path = rest[:cut], "/"
    if not authority:
        return None, None
    # Port-agnostic: the port refusal is right for a request and wrong for a
    # name being reported, so it is stripped first.
    try:
        host = host_from_authority(authority, Scheme(got.lower(), 0)).host
    except RequestUnreadable:
        head = authority.rsplit(":", 1)[0]
        try:
            host = host_from_authority(head, Scheme(got.lower(), 0)).host
        except RequestUnreadable:
            return None, None
    path = path.split("#", 1)[0].split("?", 1)[0]
    try:
        return host, normalise_path(path)
    except RequestUnreadable:
        return host, None
