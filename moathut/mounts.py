"""A box's mounts: `SRC[:DST][:ro]` from the command line, and what may
not be mounted."""

import os
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from .paths import protected


class MountRefused(ValueError):
    """A mount the box may not have, with the reason."""


class Mount(NamedTuple):
    source: Path
    target: str
    readonly: bool

    def as_json(self):
        return {"source": str(self.source), "target": self.target,
                "readonly": self.readonly}

    @classmethod
    def from_json(cls, doc):
        return cls(Path(doc["source"]), doc["target"], doc["readonly"])


def parse_mount(text, cwd, home):
    """`SRC[:DST][:ro]`. SRC is resolved, symlinks and all, since the
    checks are on what is mounted; DST defaults to it."""
    parts = text.split(":")
    readonly = False
    if len(parts) > 1 and parts[-1] in ("ro", "rw"):
        readonly = parts.pop() == "ro"
    if len(parts) > 2 or not parts[0] or (len(parts) == 2 and not parts[1]):
        raise MountRefused(f"{text!r}: expected SRC[:DST][:ro]")
    source = parts[0]
    if source == "~" or source.startswith("~/"):
        source = str(home) + source[1:]
    source = (Path(cwd) / source).resolve()
    target = parts[1] if len(parts) == 2 else str(source)
    if not os.path.isabs(target):
        raise MountRefused(f"{text!r}: {target} is not an absolute path")
    return Mount(source, os.path.normpath(target), readonly)


def _overlaps(a, b):
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


def refuse(mount, dirs, covered):
    """Raise MountRefused for a mount the box may not have. `covered` are
    the paths inside that a mount must not hide: the box's home, its
    trust store and its prompt."""
    source = mount.source
    if not source.is_dir():
        raise MountRefused(f"{source}: not a directory")
    home = dirs.home.resolve()
    if home.is_relative_to(source):
        raise MountRefused(f"{source}: is, or contains, your home directory")
    for path in protected(dirs):
        if _overlaps(source, path.resolve()):
            raise MountRefused(f"{source}: overlaps {path}")
    target = PurePosixPath(mount.target)
    for inner in covered:
        if PurePosixPath(inner).is_relative_to(target):
            raise MountRefused(f"{mount.target}: would cover {inner}")
    if any(ch in str(source) + mount.target for ch in ":,$\n"):
        raise MountRefused(f"{source}: ':', ',', '$' and newlines cannot "
                           "be written in a mount")
