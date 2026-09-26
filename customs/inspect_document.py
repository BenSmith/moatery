"""The inspector's policy document: the vocabulary its writer and reader share.

The hostname rule every list is matched by, the two TLS modes, the shape of
a policy entry and how a set of them governs a request, and the digest that
tells the document on disk from the one a running listener holds. Nothing
about a workload: no config grammar, no uid, no path. The listener imports
this and never a writer, and tests/test_closure.py holds that line.
"""

import fnmatch
import hashlib
from typing import NamedTuple


# --- Hostname vocabulary: one normalisation, one refusal, one comparison ---

def normalise_hostname(host: str) -> str:
    """A hostname in the one form every match is made against: lowercased,
    one trailing root dot removed. Otherwise the spelling is the bypass.
    """
    host = host.strip().lower()
    return host[:-1] if host.endswith(".") and host != "." else host


def hostname_control_character(host: str) -> str | None:
    """The first control character in a name, or None if it carries none.

    A name read off the wire goes into journal lines, where a bare LF would
    start a second record the guest wrote. Refused at the parse rather than
    escaped at each log site. The character is returned so each caller can
    raise its own exception type.
    """
    for ch in host:
        if ch < " " or ch == "\x7f":
            return ch
    return None


# What a guest-supplied name may be spelled with once normalised: every DNS
# name a client resolves, `_` included, and every IPv4 literal.
HOSTNAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_.")


def hostname_bad_character(host: str) -> str | None:
    """The first character in a normalised name that no name is spelled
    with, or None.

    fnmatch's `*` matches anything, so `*.example.com` would admit
    `a reason='x' .example.com`, a name that then forges a field of the
    journal line it is written into.
    """
    for ch in host:
        if ch not in HOSTNAME_CHARS:
            return ch
    return None


def hostname_match(host: str, patterns) -> bool:
    """Whether a hostname is authorised by a list of fnmatch patterns.

    fnmatchcase on normalised names, since fnmatch's case handling varies by
    platform. `*.example.com` does not match `example.com`.
    """
    host = normalise_hostname(host)
    if not host:
        return False
    return any(fnmatch.fnmatchcase(host, normalise_hostname(p))
               for p in patterns)


def patterns_overlap(a: str, b: str) -> bool:
    """Whether two fnmatch host patterns can name a host in common.

    Exact when either has no wildcard; with two wildcards it can miss a
    shared name, so a caller that must never let one through checks the
    name too.
    """
    a = normalise_hostname(a)
    b = normalise_hostname(b)
    if not a or not b:
        return False
    return a == b or fnmatch.fnmatchcase(a, b) or fnmatch.fnmatchcase(b, a)


# --- The two TLS modes ---
#
# `splice` checks the SNI and relays the connection undecrypted. `inspect`,
# the default, terminates and authorises every request inside, which is
# the only mode in which the allowlist holds per request. It needs the
# guest to trust the workload's CA; `splice` is for a guest that cannot,
# and is the widest bypass in the document.
TLS_MODES = ("splice", "inspect")
TLS_DEFAULT = "inspect"


# --- A policy entry, and how a set of them governs a request ---

class VmPolicyEntry(NamedTuple):
    """One policy entry, normalised: a host pattern and what it permits.

    `methods` and `paths` are None where the key was absent, which means
    any; an empty tuple means none. Collapsing the two fails closed, and so
    quietly.
    """

    host: str
    methods: tuple | None
    paths: tuple | None
    credential: str | None = None

    def permits(self, method: str, path: str) -> bool:
        """Whether this entry permits one method on one path. `methods` and
        `paths` are a cross product.
        """
        if self.methods is not None and method.upper() not in self.methods:
            return False
        if self.paths is not None and not any(
                fnmatch.fnmatchcase(path, pattern) for pattern in self.paths):
            return False
        return True


def policy_governs(host: str, entries) -> list[VmPolicyEntry]:
    """The entries governing one hostname, which may be none.

    A host any entry matches is governed by those entries alone and `hosts`
    is not consulted, or a wildcard in `hosts` would widen every host it
    covers. Matching entries union among themselves.
    """
    return [e for e in entries if hostname_match(host, (e.host,))]


# --- The keys the listener reads that are not lists, and the digest ---

# The key the listener reports its loaded document's digest under.
INSPECT_DIGEST_KEY = "policy_digest"


def inspect_policy_digest(text: str) -> str:
    """The digest of one policy document, over its text: the listener
    digests what it loaded and a reader what is on disk, and this is the one
    definition both use.
    """
    return hashlib.sha256(text.encode()).hexdigest()
