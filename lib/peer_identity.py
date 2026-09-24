"""Who owns the far end of an accepted connection?

Shared by the broker and the inspector. On a socket path the answer is
SO_PEERCRED; on an address it is the owner of the peer's row in the
kernel's socket table. The uid, not the source address: the host's
networking re-originates every workload's flows as that workload's own
user, so the address says nothing. The kernel reports uids through the
reader's user namespace, so the helpers at the end check that the uids
that matter can be represented at all.
"""

import ipaddress
import os
import socket
import struct
from pathlib import Path

PROC_NET_TCP = ("/proc/net/tcp", "/proc/net/tcp6")


def netns_tables(pid):
    """The socket tables of `pid`'s network namespace, for listeners bound
    there by another process."""
    return (f"/proc/{pid}/net/tcp", f"/proc/{pid}/net/tcp6")

# What a connection was aimed at before the host translated it: one option
# per family, not interchangeable.
SO_ORIGINAL_DST = 80
IPV6_ORIGINAL_DST = 80
# Asked as socket.IPPROTO_IPV6: Python has no SOL_IPV6, and the
# AttributeError would be swallowed by the lookup's tolerant except.


def _norm(addr):
    """Canonical address, with v4-mapped v6 collapsed to plain v4, so a
    dual-stack peer compares equal to its row in either table.
    """
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _proc_addr(text):
    """Decode a /proc/net address: 32-bit words, each little-endian, in hex."""
    raw = bytes.fromhex(text)
    return _norm(b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4)))


def local_endpoints(sock):
    """Every endpoint this connection's local end may be recorded under.

    The peer's row records the address it dialled, not the one the
    redirect delivered it to, so SO_ORIGINAL_DST is read as well as
    getsockname().
    """
    endpoints = [tuple(sock.getsockname()[:2])]
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, packed = struct.unpack("!2xH4s8x", raw)
        endpoints.append((socket.inet_ntoa(packed), port))
    except (OSError, struct.error):
        pass  # no conntrack entry, or this is a v6 socket: try v6 below
    # Both families: a v6 dial is translated too, and without its original
    # address nothing would match and every v6 caller would be admitted as
    # unresolved. The scope id is dropped, since /proc records none.
    try:
        raw = sock.getsockopt(socket.IPPROTO_IPV6, IPV6_ORIGINAL_DST, 28)
        port, packed = struct.unpack("!2xH4x16s4x", raw)
        endpoints.append((socket.inet_ntop(socket.AF_INET6, packed), port))
    except (OSError, struct.error):
        pass  # no conntrack entry: nothing translated this
    return endpoints


def _peer_rows(rows, locals_, peer):
    """(uid, inode) of every row that is `peer`'s end of this connection.

    That row is this connection mirrored: its local address is our remote,
    its remote one of `locals_`. The port substring test is a cheap filter
    before the full parse, since a caller should not be able to make every
    connection pay for the host's whole table.
    """
    want_local = (_norm(peer[0]), peer[1])
    want_remotes = {(_norm(host), port) for host, port in locals_}
    needle = f":{peer[1]:04X}"
    for line in rows:
        if needle not in line:
            continue
        f = line.split()
        if len(f) < 10:
            continue
        try:
            local_host, local_port = f[1].split(":")
            if (_proc_addr(local_host), int(local_port, 16)) != want_local:
                continue
            remote_host, remote_port = f[2].split(":")
            remote = (_proc_addr(remote_host), int(remote_port, 16))
            if remote not in want_remotes:
                continue
            yield int(f[7]), int(f[9])
        except ValueError:
            continue


def peer_uid_from(rows, locals_, peer):
    """uid owning `peer`'s socket, given /proc/net/tcp data lines, or None.
    A row with inode 0 has no owning socket and names nobody, not root.
    """
    for uid, inode in _peer_rows(rows, locals_, peer):
        if inode != 0:
            return uid
    return None


def peer_orphaned_from(rows, locals_, peer):
    """Whether `peer`'s row is there and owned by no socket: the caller
    wrote and closed before it was looked up, which any caller can choose
    to do.
    """
    found = list(_peer_rows(rows, locals_, peer))
    return bool(found) and all(inode == 0 for _uid, inode in found)


def _proc_tables(paths=PROC_NET_TCP):
    """The data lines of each /proc/net table that can be read."""
    for path in paths:
        try:
            with open(path) as fh:
                yield fh.readlines()[1:]
        except OSError:
            continue


def peer_uid(locals_, peer):
    """uid owning the far end of an accepted connection, or None."""
    for rows in _proc_tables():
        uid = peer_uid_from(rows, locals_, peer)
        if uid is not None:
            return uid
    return None


def peer_caller(locals_, peer, tables=PROC_NET_TCP):
    """(uid or None, orphaned) for the far end of an accepted connection,
    from one read of each of `tables`.
    """
    orphaned = False
    for rows in _proc_tables(tables):
        uid = peer_uid_from(rows, locals_, peer)
        if uid is not None:
            return uid, False
        orphaned = orphaned or peer_orphaned_from(rows, locals_, peer)
    return None, orphaned


def listed_in(sock, tables=PROC_NET_TCP):
    """Whether `sock` has a row in one of `tables`, by inode; None if none
    of them can be read.

    A listener is in the table of the namespace it was bound in, and its
    callers are in the same one. A lookup that reads another namespace's
    table finds no caller at all.
    """
    inode = str(os.fstat(sock.fileno()).st_ino)
    read = False
    for rows in _proc_tables(tables):
        read = True
        for line in rows:
            f = line.split()
            if len(f) >= 10 and f[9] == inode:
                return True
    return False if read else None


# The credentials of an AF_UNIX peer as the kernel hands them over: pid,
# uid, gid, each a C int.
SO_PEERCRED_FORMAT = "3i"


def peer_uid_unix(sock):
    """uid owning the far end of an accepted AF_UNIX connection, or None.

    On another family the kernel answers uid -1 rather than refusing, so the
    family is checked and the wrong one raises.
    """
    if sock.family != socket.AF_UNIX:
        raise OSError(f"SO_PEERCRED answers only for AF_UNIX, not "
                      f"{sock.family!r}")
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                          struct.calcsize(SO_PEERCRED_FORMAT))
    _pid, uid, _gid = struct.unpack(SO_PEERCRED_FORMAT, raw)
    return None if uid == -1 else uid


def userns_ranges(uid_map):
    """The uid ranges this namespace can represent, as (start, count), in
    the namespace's own numbering: the first column of uid_map, which is
    what the kernel reports to a reader here.
    """
    ranges = []
    for line in uid_map.splitlines():
        f = line.split()
        if len(f) != 3:
            continue
        try:
            ranges.append((int(f[0]), int(f[2])))
        except ValueError:
            continue
    return ranges


def userns_maps_everything(uid_map):
    """Whether this is an unrestricted namespace -- the initial one, in
    practice."""
    return any(start == 0 and count >= 0xFFFFFFFF
               for start, count in userns_ranges(uid_map))


def unmappable_uids(uids, uid_map):
    """The uids among `uids` this namespace cannot represent. Checked
    against the uids that matter, since a restricted namespace can still
    map the whole workload range.
    """
    ranges = userns_ranges(uid_map)
    return [uid for uid in uids
            if not any(start <= uid < start + count
                       for start, count in ranges)]


def overflow_uid():
    """The uid the kernel substitutes for one it cannot map."""
    try:
        return int(Path("/proc/sys/kernel/overflowuid").read_text().strip())
    except (OSError, ValueError):
        return 65534
