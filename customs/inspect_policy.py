"""The inspector's policy document, as the listener holds it.

`load_policy` reads the JSON document once, at start, into a `Policy` that
is never edited after, so an edited document applies on a restart. The
hostname rule and the entry matcher are inspect_document's, shared with
whatever writes the document; this module imports no writer.
"""

import json
from typing import NamedTuple

from .inspect_document import (
    TLS_DEFAULT,
    TLS_MODES,
    hostname_match,
    inspect_policy_digest,
    normalise_hostname,
    patterns_overlap,
    policy_governs,
    VmPolicyEntry,
)


class Policy(NamedTuple):
    """One workload's inspection lists, as read at start or at a reload.
    Tuples, since nothing may edit them after load: a reload replaces the
    whole.

    `internal_expected` admits nothing. It names the hosts the host's
    own private-address rule excepts, so a failed dial into private space
    can be reported as a missing exception rather than a host that is
    down. The name says what the entries are -- hosts expected to sit in
    private space -- rather than reading as a list that admits.
    """

    tls: str
    hosts: tuple
    internal_expected: tuple = ()
    splice: tuple = ()
    policy: tuple = ()
    # The digest of the text parsed, echoed into the status file so a reader
    # can tell a listener enforcing the file on disk from one holding an older
    # one.
    digest: str = ""

    @property
    def summary(self) -> str:
        return (f"tls={self.tls} hosts={len(self.hosts)} "
                f"internal_expected={len(self.internal_expected)} "
                f"splice={len(self.splice)} "
                f"policy={len(self.policy)}")

    def admits(self, host: str) -> bool:
        """Whether this name is on a list at all: the question at the front of
        a connection, before any request. A `policy` entry admits its own host.
        """
        return (hostname_match(host, self.hosts)
                or bool(policy_governs(host, self.policy)))

    def permits(self, host: str, method: str, path: str) -> bool:
        """Whether one request is authorised.

        A host any `policy` entry matches is governed by those entries alone,
        and `hosts` is not consulted for it, so a wildcard in `hosts` cannot
        widen a host an entry restricts. Among the governing entries it is
        union, so the order of the file never changes what is allowed.
        """
        governing = policy_governs(host, self.policy)
        if governing:
            return any(e.permits(method, path) for e in governing)
        return hostname_match(host, self.hosts)

    def governs(self, host: str) -> bool:
        """Whether any policy entry names this host."""
        return bool(policy_governs(host, self.policy))

    def splices(self, host: str) -> bool:
        """Whether this host is exempt from termination, by mode or by list.

        Never a host a policy entry governs, whose rules would then never run.
        load_policy refuses a `splice` pattern that overlaps an entry; this
        holds for the names two wildcards share, which that check cannot see.
        """
        if self.tls == "splice":
            return True
        return (hostname_match(host, self.splice)
                and not self.governs(host))

    def credential_for(self, host: str):
        """The credential name this host's requests are brokered with, or None.

        It decides only where a request goes. Where two governing entries name
        different credentials the first in the file wins, rather than failing
        a hand-edited document at start.
        """
        for entry in policy_governs(host, self.policy):
            if entry.credential:
                return entry.credential
        return None


def load_policy(path):
    """Read the policy document, or raise.

    There is no default: an empty policy is a valid one, so a fallback could
    not be told from an operator who allowed nothing.
    """
    with open(path) as f:
        text = f.read()
    # From the text parsed, not a second read: a rewrite between the two would
    # advertise the new digest while enforcing the old document.
    digest = inspect_policy_digest(text)
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError(
            f"{path}: expected a JSON object, got {type(doc).__name__}")
    # One of two words or refused: every branch asks for "inspect" or
    # "splice", and an unknown mode would skip the CA check and splice
    # everything.
    tls = doc.get("tls")
    if tls is None:
        tls = TLS_DEFAULT
    if tls not in TLS_MODES:
        raise ValueError(
            f"{path}: 'tls' is {tls!r}; it is one of "
            + ", ".join(repr(m) for m in TLS_MODES))
    hosts = _names(doc, "hosts", path)
    internal_expected = _names(doc, "internal_expected", path)
    splice = _names(doc, "splice", path)
    _refuse_http2(doc, path)
    _refuse_renamed_internal(doc, path)
    entries = doc.get("policy")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'policy' is not a list")
    policy = []
    for item in entries:
        if (not isinstance(item, dict)
                or not isinstance(item.get("host"), str)
                or not item["host"].strip()):
            raise ValueError(f"{path}: a 'policy' entry is not a table with a "
                             f"host: {item!r}")
        # None and [] differ: absent is any, empty is none. Methods are
        # uppercased here too, since permits compares `method.upper()` and a
        # hand-written `["get"]` would otherwise deny every GET.
        methods = item.get("methods")
        paths = item.get("paths")
        for key, value in (("methods", methods), ("paths", paths)):
            # A string is refused rather than iterated as one-letter members.
            if value is not None and not isinstance(value, list):
                raise ValueError(
                    f"{path}: policy entry {item['host']!r}: {key!r} is not "
                    f"a list or null")
            for member in value or ():
                if not isinstance(member, str) or not member.strip():
                    raise ValueError(
                        f"{path}: policy entry {item['host']!r}: {key!r} "
                        f"holds {member!r}, which is not a "
                        f"{'method' if key == 'methods' else 'path pattern'}")
        # Absent and null are the same. A non-string credential is dropped
        # rather than refused, so the host goes unbrokered and says so in the
        # record instead of failing the start.
        credential = item.get("credential")
        if not isinstance(credential, str) or not credential.strip():
            credential = None
        else:
            credential = credential.strip()
        policy.append(VmPolicyEntry(
            host=item["host"],
            methods=None if methods is None else tuple(
                m.upper() for m in methods),
            paths=None if paths is None else tuple(paths),
            credential=credential))
    _refuse_inert_entries(path, tls, policy, splice)
    return Policy(tls=tls, hosts=tuple(hosts),
                  internal_expected=tuple(
                      normalise_hostname(h) for h in internal_expected),
                  splice=tuple(splice), policy=tuple(policy), digest=digest)


def _names(doc, key, path):
    """One of the document's name lists: absent is empty, and every entry is
    a non-empty string, checked here rather than on the first connection.
    """
    value = doc.get(key)
    if value is None:
        return []
    # `{}` or `""` is a key of the wrong type, not an empty list.
    if not isinstance(value, list):
        raise ValueError(f"{path}: {key!r} is not a list")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"{path}: {key!r} holds {item!r}, which is not a host name "
                f"or pattern")
    return value


def _refuse_http2(doc, path):
    """Refuse an `http2` list that names a host.

    Every terminated host is offered HTTP/1.1 alone. Ignored, the list would
    leave a client that speaks only h2 failing against its host with nothing
    here saying why. An empty one is what a writer that always emits the key
    sends, and says nothing.
    """
    names = _names(doc, "http2", path)
    if names:
        raise ValueError(
            f"{path}: 'http2' names {', '.join(map(repr, names))}: HTTP/2 is "
            f"not relayed, and every terminated host is offered HTTP/1.1 "
            f"alone. A host whose client speaks only h2 (gRPC) goes in "
            f"'splice', where its h2 runs end to end and the host is checked "
            f"by name alone")


def _refuse_renamed_internal(doc, path):
    """Refuse the old name of the private-address list rather than read it
    as empty.

    The list was `internal`; it is `internal_expected`, so the key says what
    the entries are rather than reading as a list that admits. A writer
    still sending a non-empty `internal` is told, not silently ignored:
    ignored, every private-address refusal files as a host that is down and
    the counter that names it never moves. An empty one says nothing and is
    accepted, as a writer that always emits the key sends.
    """
    if _names(doc, "internal", path):
        raise ValueError(
            f"{path}: 'internal' is now 'internal_expected'; rename the key. "
            f"It names the hosts the operator has given a private address, "
            f"and admits nothing")


def _refuse_inert_entries(path, tls, entries, splice):
    """Refuse a document whose policy entries could never run.

    `methods` and `paths` need a decrypted request, which the whole-workload
    splice and a per-host splice each leave a host without. Such an entry is
    refused at start, naming both halves, rather than one half being ignored.
    """
    if not entries:
        return
    if tls == "splice":
        raise ValueError(
            f"{path}: 'policy' entries with tls 'splice': a spliced "
            f"connection is never decrypted, so no entry's methods, paths "
            f"or credential could apply. Use tls 'inspect' and splice only "
            f"the hosts that cannot take the CA, or drop the entries")
    for entry in entries:
        for pattern in splice:
            if patterns_overlap(entry.host, pattern):
                raise ValueError(
                    f"{path}: policy entry {entry.host!r} overlaps "
                    f"'splice' entry {pattern!r}: that host is never read "
                    f"as an HTTP request, so the entry could never run. "
                    f"Keep one of the two")
