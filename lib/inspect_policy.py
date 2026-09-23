"""The inspector's policy document, as the listener holds it.

`load_policy` reads the JSON document once, at start, into a `Policy` that
is never edited after, so an edited document applies on a restart. The
hostname rule and the entry matcher are inspect_document's, shared with
whatever writes the document; this module imports no writer.
"""

import json
from typing import NamedTuple

from inspect_document import (
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
    """One workload's inspection lists, as read at start. Tuples, since
    nothing may edit them after load.

    `internal` admits nothing. It names the hosts the host's own
    private-address rule excepts, so a failed dial into private space can be
    reported as a missing exception rather than a host that is down.
    """

    tls: str
    hosts: tuple
    internal: tuple = ()
    splice: tuple = ()
    http2: tuple = ()
    policy: tuple = ()
    # The digest of the text parsed, echoed into the status file so a reader
    # can tell a listener enforcing the file on disk from one holding an older
    # one.
    digest: str = ""

    @property
    def summary(self) -> str:
        return (f"tls={self.tls} hosts={len(self.hosts)} "
                f"internal={len(self.internal)} splice={len(self.splice)} "
                f"http2={len(self.http2)} policy={len(self.policy)}")

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

    def speaks_h2(self, host: str) -> bool:
        """Whether this terminated host is offered h2 and relayed by frame.

        Never a host a policy entry governs: an h2 request's headers are
        relayed compressed, so there is no request line to match.
        """
        return hostname_match(host, self.http2) and not self.governs(host)

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
    internal = _names(doc, "internal", path)
    splice = _names(doc, "splice", path)
    # Patterns are not normalised here; hostname_match normalises both sides.
    http2 = _names(doc, "http2", path)
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
    _refuse_inert_entries(path, tls, policy, splice, http2)
    return Policy(tls=tls, hosts=tuple(hosts),
                  internal=tuple(normalise_hostname(h) for h in internal),
                  splice=tuple(splice), http2=tuple(http2),
                  policy=tuple(policy), digest=digest)


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


def _refuse_inert_entries(path, tls, entries, splice, http2):
    """Refuse a document whose policy entries could never run.

    `methods` and `paths` need a decrypted HTTP/1.1 request, which the
    whole-workload splice, a per-host splice and h2 each leave a host
    without. Such an entry is refused at start, naming both halves, rather
    than one half being ignored.
    """
    if not entries:
        return
    if tls == "splice":
        raise ValueError(
            f"{path}: 'policy' entries with tls 'splice': a spliced "
            f"connection is never decrypted, so no entry's methods, paths "
            f"or credential could apply. Use tls 'inspect' and splice only "
            f"the hosts that cannot take the CA, or drop the entries")
    for key, patterns in (("splice", splice), ("http2", http2)):
        for entry in entries:
            for pattern in patterns:
                if patterns_overlap(entry.host, pattern):
                    raise ValueError(
                        f"{path}: policy entry {entry.host!r} overlaps "
                        f"{key!r} entry {pattern!r}: that host is never "
                        f"read as an HTTP/1.1 request, so the entry could "
                        f"never run. Keep one of the two")
