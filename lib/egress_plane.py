"""egress_plane: the two ports the egress redirect catches, and what each is.

A plane is which port the guest dialled, 80 or 443. Each row carries the
three facts both ends of the redirect spell: the port the guest dialled,
the port the redirect lands it on, which the socket unit binds, and the
label a record names it by.
"""

from typing import NamedTuple


class Plane(NamedTuple):
    label: str
    """What a record and `--plane` call it."""
    guest_port: int
    """What the guest dialled; the port the redirect matches."""
    inspect_port: int
    """Where the redirect lands it; the port the socket unit binds."""


CLEARTEXT = Plane("cleartext", 80, 8080)
TLS = Plane("tls", 443, 8443)

PLANES = (CLEARTEXT, TLS)


def plane_for_port(port: int) -> Plane | None:
    """The plane a listener accepting on `port` carries, or None for a port
    that is not one of ours."""
    for plane in PLANES:
        if port == plane.inspect_port:
            return plane
    return None
