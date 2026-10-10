"""What `moathut cp` sends a hut and takes from one: tar streams, which
the hut's own tar, run as its user, reads and writes on its side."""

import os
import tarfile
import tempfile


class ArchiveRefused(Exception):
    """An archive a hut sent that is not taken."""


def pack(sources, names, stream, warn):
    """SOURCES as a tar archive on STREAM, each under its name in NAMES.
    A source named through a link is sent as what it points to, as cp
    does; a link inside one is sent as a link, so the hut is given the
    link and not what it points to on the host."""
    with tarfile.open(fileobj=stream, mode="w|") as archive:
        for source, name in zip(sources, names):
            archive.add(os.path.realpath(source), arcname=name,
                        filter=lambda info: _sendable(info, warn))


def _sendable(info, warn):
    if not (info.isreg() or info.isdir() or info.issym() or info.islnk()):
        warn(f"{info.name!r} is not a file, a directory or a link; not sent")
        return None
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def take(stream, into, base, name, warn):
    """Unpack the archive on STREAM, which a hut sent and which holds BASE
    and what is under it, and move BASE into INTO as NAME, a path that
    must not exist. It is unpacked into a directory made empty for it,
    so nothing already in INTO is reached through what it holds; no link
    is taken, since one points wherever the hut chose; and nothing but
    BASE is moved out."""
    with tempfile.TemporaryDirectory(prefix=".moathut-cp-",
                                     dir=into) as staging:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            archive.extractall(staging, filter=_taking(base, warn))
        taken = os.path.join(staging, base)
        if not os.path.lexists(taken):
            raise ArchiveRefused(f"it sent no {base!r}")
        target = os.path.join(into, name)
        if os.path.lexists(target):
            raise ArchiveRefused(f"{target} exists")
        os.rename(taken, target)
    return target


def _under(base, path):
    parts = path.rstrip("/").split("/")
    return parts[0] == base and ".." not in parts


def _taking(base, warn):
    def check(member, path):
        if not _under(base, member.name):
            raise ArchiveRefused(f"it sent {member.name!r}, which is not "
                                 f"under {base!r}")
        if member.issym():
            warn(f"{member.name!r}, a link; not taken")
            return None
        if member.islnk() and not _under(base, member.linkname):
            raise ArchiveRefused(f"it sent {member.name!r}, a link to "
                                 f"{member.linkname!r}, which is not under "
                                 f"{base!r}")
        if not (member.isreg() or member.isdir() or member.islnk()):
            warn(f"{member.name!r}, which is not a file or a directory; "
                 "not taken")
            return None
        return tarfile.data_filter(member, path)
    return check
