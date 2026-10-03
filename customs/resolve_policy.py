"""What the synthesising responder answers, and what it counts as listed.

One address per family, from the command line, for every name but the
static ones: a name the static map carries is answered from the map, with
the addresses the workload's filter admits for it. The inspector's policy
is read to count, never to answer: a query for a name no list admits is
the signature of something encoding data into names, and it is answered
exactly like any other.
"""

import ipaddress
import json

from .inspect_document import normalize_hostname
from .resolve_wire import TYPE_AAAA

# The answer for a name never changes while the responder runs, so a long
# TTL costs nothing and spares the workload a query per connection.
RESOLVE_TTL = 3600


class Policy:
    """The responder's answers, fixed at start.

    `admits` is the inspector's own question, whether a name is on any list
    (inspect_policy.Policy.admits), so the two cannot disagree about what
    is listed. With no v6 address an AAAA gets an empty answer: an address
    the redirect does not cover would send the workload's client to a
    listener that is not there, and a dual-stack client falls back to v4
    only after waiting on it.

    `static` maps a name to the addresses it is answered with instead: a
    destination reached past the inspector, on a port it does not serve,
    whose connection would hang at a synthesised address rather than be
    refused. Its keys are normalised, and a name in it is on a list.
    """

    def __init__(self, address, address6=None, admits=None,
                 ttl=RESOLVE_TTL, static=None):
        self.address = address
        self.address6 = address6
        self._admits = admits
        self.ttl = ttl
        self.static = {normalize_hostname(name): tuple(addresses)
                       for name, addresses in (static or {}).items()}

    def readmit(self, admits):
        """Count against another document's lists from the next query."""
        self._admits = admits

    def on_a_list(self, name: str) -> bool:
        return name in self.static or (
            self._admits is not None and self._admits(name))

    def answers(self, name, qtype):
        """The addresses an A or AAAA is answered with, and their source.

        Returns (addresses, "static" or "synthesised"); no addresses is
        NODATA. A static name is answered from the map alone: one with no
        address in the family asked gets NODATA, not the synthesised one,
        which would send the workload to a listener that does not serve
        the port it wants.
        """
        want6 = qtype == TYPE_AAAA
        entry = self.static.get(name)
        if entry is not None:
            return (tuple(a for a in entry if (":" in a) == want6),
                    "static")
        if want6:
            return ((self.address6,) if self.address6 else ()), "synthesised"
        return (self.address,), "synthesised"


def load_static(path):
    """The static map in `path`: a JSON object of name to address list.

    Refused whole, as ValueError, over anything but that shape or over an
    address that does not parse, so a bad entry stops the responder at
    start rather than answering its name SERVFAIL on every query. The
    addresses come back in canonical form.
    """
    with open(path) as f:
        document = json.load(f)
    if not isinstance(document, dict):
        raise ValueError("the static map is not a JSON object")
    static = {}
    for name, addresses in document.items():
        # Strings only: ip_address takes an integer too, and 5 is 0.0.0.5.
        if not isinstance(addresses, list) or \
                not all(isinstance(a, str) for a in addresses):
            raise ValueError(f"{name!r}: the addresses are not a list of "
                             f"strings")
        try:
            static[name] = [str(ipaddress.ip_address(a)) for a in addresses]
        except ValueError as exc:
            raise ValueError(f"{name!r}: {exc}") from None
    return static
