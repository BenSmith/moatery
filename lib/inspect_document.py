"""The inspector's policy document: the vocabulary its writer and reader share.

The egress inspector reads one JSON document at start and decides every
connection by it. This module is what BOTH ends of that document agree on
and nothing else: the hostname rule every list is matched by, the two TLS
modes, the shape of a policy entry and how a set of them governs a request,
the keys the listener echoes back, and the digest that lets a reader tell
the document on disk from the one a running listener holds.

WHAT IS NOT HERE, AND WHY THE LINE IS WHERE IT IS

Nothing about a workload. No config grammar, no uid, no path under /run
or /var. Whatever writes this document from a workload's configuration
lives above this module; the listener that reads it back lives in
inspect_policy and inspect_listener, which import THIS and never a writer.
The document is the whole interface between the two halves,
so the listener's closure has no reason to contain the config grammar --
and a listener that imported one would be one that could only ever be
started by that one tool, on a host laid out the way it lays one out.

The rule this module keeps: the listener side (inspect_*, egress_ca,
egress_mint, egress_upstream, egress_relay, egress_record, http_*,
tls_hello) imports from here and from each other, and from nothing that
knows what a workload is. tests/test_closure.py holds that line.

Every name here is spelled at least twice -- once by the code that writes,
once by the code that reads back -- which is the reason a constant here is a
constant rather than a literal: a drift between the two turns a real refusal
into a figure that reads zero, which is indistinguishable from a refusal
that never fired.
"""

import fnmatch
import hashlib
from typing import NamedTuple


# --- Hostname vocabulary: one normalisation, one refusal, one comparison ---
#
# Every entrypoint asks the same questions of a name, and a second answer to
# "what is this name" is a name the guest can spell twice.

def normalise_hostname(host: str) -> str:
    """A hostname in the one form every match in this design is made against.

    Lowercased and stripped of a single trailing root dot. Both halves matter:
    DNS names are case-insensitive, and `example.com.` and `example.com` are
    the same name -- a workload that writes either spelling must get the same
    decision, or the spelling becomes the bypass.

    Defined HERE, at the bottom, because whatever writes the document and
    the listener that reads it both normalise, and they have to normalise the
    same way: a pattern the writer accepted under one rule and the listener
    matched under another is a rule that reads as written and enforces
    something else. A writer imports it from here; the listener never imports
    a writer.
    """
    host = host.strip().lower()
    return host[:-1] if host.endswith(".") and host != "." else host


def hostname_control_character(host: str) -> str | None:
    """The first control character in a name, or None if it carries none.

    A name read off the wire — an SNI, a DNS label — is bytes a guest chose,
    and both readers of one decode ASCII rather than refusing it: a control
    character is ASCII. The name then reaches a `print()` whose destination is
    the journal, where a bare LF ends the record and the rest of the name
    becomes a SECOND entry, indistinguishable from one this program wrote. A
    guest that can write `evil.com\\nsplice plane=tls … host=github.com` can
    forge the evidence an operator reads a decision from. The same name is
    also carried into the status document.

    Refused, not escaped, and refused at the parse — the reason
    `_reject_controls` in the cleartext plane gives for the same character
    class: a field with a line ending inside it has no reading both ends share,
    and rewriting one into something harmless is picking a reading. No name
    that reaches a decision here needs one, so the parse is where it stops
    rather than every log site having to remember.

    Returns the character so the caller can name it in ITS own exception type
    and disposition: an unreadable hello and a malformed query are already
    counted differently, and a shared raise would flatten them.
    """
    for ch in host:
        if ch < " " or ch == "\x7f":
            return ch
    return None


def hostname_match(host: str, patterns) -> bool:
    """Whether a hostname is authorised by a list of fnmatch patterns.

    `fnmatch.fnmatchcase`, not `fnmatch.fnmatch`. The plain form normalises
    its arguments through os.path.normcase, which is a no-op on Linux and
    lowercases on other platforms -- so it is case-insensitive only by
    accident of platform. Both sides are normalised here instead, which is
    the same answer everywhere.

    The apex trap is kept, not fixed: `*.example.com` does not authorise
    `example.com`. That is fnmatch's behaviour and what every list is
    written against; a change that quietly widened it would silently grant
    every existing policy a destination its operator did not write down.
    """
    host = normalise_hostname(host)
    if not host:
        return False
    return any(fnmatch.fnmatchcase(host, normalise_hostname(p))
               for p in patterns)


def patterns_overlap(a: str, b: str) -> bool:
    """Whether two fnmatch host patterns can name a host in common.

    Yes when either matches the other read as a literal, which is exact
    whenever at least one of the two carries no wildcard -- the ordinary
    case, an entry's host against a list's pattern -- and an approximation
    when both do: `*.a.example.com` and `*.b.example.com` overlap on nothing
    and this says so, but two wildcards can share a name neither matches as
    a literal. A caller that must never let a shared name through checks the
    name as well, where there is one.
    """
    a = normalise_hostname(a)
    b = normalise_hostname(b)
    if not a or not b:
        return False
    return a == b or fnmatch.fnmatchcase(a, b) or fnmatch.fnmatchcase(b, a)


# --- The two TLS modes ---
# What a filtered workload's redirected TLS connections get.
#
# `splice` reads the ClientHello's SNI, matches it against `hosts`, and replays
# those exact bytes upstream. Nothing is decrypted; the guest's handshake is
# with the origin, and this host never holds a key to it.
#
# `inspect` terminates. The inspector completes the guest's handshake itself
# with a leaf minted by this workload's own CA, opens a separately verified
# session to the origin, and authorises every REQUEST inside. It is the default
# because the property the allowlist claims -- that the guest reaches these
# hosts and no others -- is only true per request under termination: under
# `splice` a name is checked once, at the front of a connection whose contents
# nothing can see.
#
# THE DEFAULT IS NOT FREE. A terminated guest must trust the workload's CA,
# which whoever provisions the guest has to put there before the guest is
# first started. A guest that does not hold it gets certificate errors on
# every HTTPS request until it is re-provisioned. `"splice"` is the answer
# for a guest that cannot hold a CA, and is fully supported -- it is a
# weaker property, not a deprecated one.
#
# It is also the widest bypass in this document: every host, not a named
# one.
TLS_MODES = ("splice", "inspect")
TLS_DEFAULT = "inspect"


# --- A policy entry, and how a set of them governs a request ---

class VmPolicyEntry(NamedTuple):
    """One policy entry, normalised: a host pattern and what it permits.

    `methods` and `paths` are `None` where the key was absent, NOT an empty
    tuple, and the difference is the whole of the widening trap: absent means
    "any", empty would mean "none". Collapsing the two makes a single-entry
    host with no `paths` deny everything instead of permitting everything --
    the failure in the safe direction, which is why it survives review.
    """

    host: str
    methods: tuple | None
    paths: tuple | None
    credential: str | None = None

    def permits(self, method: str, path: str) -> bool:
        """Whether this entry permits one method on one path.

        `methods` and `paths` inside one entry are a CROSS PRODUCT: two of each
        permit all four combinations. An absent key is "any", the shorthand
        the single-entry case reads naturally as.
        """
        if self.methods is not None and method.upper() not in self.methods:
            return False
        if self.paths is not None and not any(
                fnmatch.fnmatchcase(path, pattern) for pattern in self.paths):
            return False
        return True


def policy_governs(host: str, entries) -> list[VmPolicyEntry]:
    """The entries governing one hostname, which may be none.

    The composition rule lives here and is the thing to get right: a host with
    any matching entry is governed by THOSE ENTRIES ALONE, and `hosts` is not
    consulted for it. The careless reading -- a `hosts` entry is a `policy`
    entry with no keys, so union them -- silently destroys the feature: one
    wildcard written for an unrelated reason contributes "any method, any path"
    to every host it happens to cover, and the diff that introduced it looks
    like it ADDED access rather than removing a restriction.

    Host patterns union among themselves, so `*.example.com` and
    `api.example.com` both govern `api.example.com` and neither overrides the
    other. That is the apex trap's sibling, and it is why anything that
    reports on a policy should print the EFFECTIVE rules per host rather
    than the file's entries.
    """
    return [e for e in entries if hostname_match(host, (e.host,))]


# --- The keys the listener reads that are not lists, and the digest ---

# The key the listener echoes its loaded document's digest under. Named here
# rather than spelled at both ends: the writer is the listener and the
# reader is whatever compares the document on disk with the one loaded, and
# a typo in either would read as "an older listener that does not report a
# digest", which is the one state the check treats as silence.
INSPECT_DIGEST_KEY = "policy_digest"


def inspect_policy_digest(text: str) -> str:
    """The digest of one policy document.

    THE ONE PRODUCER: the listener digests the bytes it loaded and a reader
    digests the bytes on disk, and the two are compared for equality. A
    hashlib call at each end
    would be two definitions of that comparison, and the failure mode of a
    disagreement is not a missed alarm -- it is a PERMANENT one, on every
    inspected workload on the host, which is how a signal stops being read.

    Over the text rather than over the parsed document, because the text is
    what both sides have: the listener holds the string it read, and the
    reader holds the file. Digesting a re-parsed structure would also make the
    value depend on this Python's dict ordering rather than on the file.
    """
    return hashlib.sha256(text.encode()).hexdigest()
