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

TABLE_NAMES = ("net/tcp", "net/tcp6")


class NoSocketTable(Exception):
    """None of a namespace's socket tables could be read."""


class SocketTables:
    """The TCP socket tables of one network namespace, read from a /proc
    directory: this process's own, or another's.

    Another process's directory is held open from the start, so once that
    process has gone its tables cannot be read at all, rather than being
    those of whichever process is later given its pid.
    """

    def __init__(self, directory=None):
        self.directory = directory
        self._dir_fd = None
        if directory is None:
            return
        try:
            self._dir_fd = os.open(
                directory, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            # Read as no table at all.
            pass

    def _open(self, name):
        if self.directory is None:
            return open(f"/proc/self/{name}")
        if self._dir_fd is None:
            raise FileNotFoundError(f"{self.directory}/{name}")
        return open(name,
                    opener=lambda path, flags: os.open(path, flags,
                                                       dir_fd=self._dir_fd))

    def read(self):
        """The data lines of each table that can be read."""
        for name in TABLE_NAMES:
            try:
                with self._open(name) as fh:
                    lines = fh.readlines()[1:]
            except OSError:
                continue
            yield lines


OWN_TABLES = SocketTables()


def netns_tables(pid):
    """The socket tables of `pid`'s network namespace, for listeners bound
    there by another process."""
    return SocketTables(f"/proc/{pid}")

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


def peer_uid(locals_, peer):
    """uid owning the far end of an accepted connection, or None."""
    for rows in OWN_TABLES.read():
        uid = peer_uid_from(rows, locals_, peer)
        if uid is not None:
            return uid
    return None


def peer_caller(locals_, peer, tables=OWN_TABLES):
    """(uid or None, orphaned) for the far end of an accepted connection,
    from one read of each of `tables`. Raises NoSocketTable if none can be
    read: a caller found in no table is then no sign of churn.
    """
    orphaned = read = False
    for rows in tables.read():
        read = True
        uid = peer_uid_from(rows, locals_, peer)
        if uid is not None:
            return uid, False
        orphaned = orphaned or peer_orphaned_from(rows, locals_, peer)
    if not read:
        raise NoSocketTable(tables.directory or "/proc/self")
    return None, orphaned


# The first byte of the kernel's struct tcp_info: the connection's state.
TCP_ESTABLISHED = 1


def peer_closed(sock):
    """Whether the far end of an accepted TCP connection has already closed
    or reset it. A reset leaves no row in the table at all, so a caller the
    lookup could not name is only innocent while its connection is up.
    """
    info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 1)
    return info[0] != TCP_ESTABLISHED


def listed_in(sock, tables=OWN_TABLES):
    """Whether `sock` has a row in one of `tables`, by inode; None if none
    of them can be read.

    A listener is in the table of the namespace it was bound in, and its
    callers are in the same one. A lookup that reads another namespace's
    table finds no caller at all.
    """
    inode = str(os.fstat(sock.fileno()).st_ino)
    read = False
    for rows in tables.read():
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


def namespace_uids(pid):
    """The uids of `pid`'s user namespace as (start, count) ranges, in this
    process's numbering, which is how the socket tables report them; None
    if the map cannot be read.

    Read from another namespace, uid_map's second column is already in the
    reader's; read from the same one, the first column is.
    """
    try:
        uid_map = Path(f"/proc/{pid}/uid_map").read_text()
        ours = os.stat("/proc/self/ns/user")
        theirs = os.stat(f"/proc/{pid}/ns/user")
    except OSError:
        return None
    if (ours.st_dev, ours.st_ino) == (theirs.st_dev, theirs.st_ino):
        return userns_ranges(uid_map)
    ranges = []
    for line in uid_map.splitlines():
        f = line.split()
        if len(f) != 3:
            continue
        try:
            ranges.append((int(f[1]), int(f[2])))
        except ValueError:
            continue
    return ranges


def in_ranges(uid, ranges):
    return any(start <= uid < start + count for start, count in ranges)


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
    return [uid for uid in uids if not in_ranges(uid, ranges)]


def overflow_uid():
    """The uid the kernel substitutes for one it cannot map."""
    try:
        return int(Path("/proc/sys/kernel/overflowuid").read_text().strip())
    except (OSError, ValueError):
        return 65534
