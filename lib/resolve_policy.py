"""What the synthesising responder answers, and what it counts as listed.

One address per family, from the command line, for every name. The
inspector's policy is read to count, never to answer: a query for a name
no list admits is the signature of something encoding data into names,
and it is answered exactly like any other.
"""

from resolve_wire import TYPE_AAAA

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
    """

    def __init__(self, address, address6=None, admits=None,
                 ttl=RESOLVE_TTL):
        self.address = address
        self.address6 = address6
        self._admits = admits
        self.ttl = ttl

    def on_a_list(self, name: str) -> bool:
        return self._admits is not None and self._admits(name)

    def answers(self, qtype):
        """The addresses an A or AAAA is answered with: one, or none."""
        if qtype == TYPE_AAAA:
            return (self.address6,) if self.address6 else ()
        return (self.address,)
