"""The bounded per-host counter and the status file it is written into.

Every per-host figure is keyed on a name the guest can choose, and anything
exporting the file as metrics would carry that cardinality onto the host. So
a map holds at most `top_n` names, first seen, and counts the rest in
`(other)`: events, not distinct hosts, which a bounded structure cannot
count. A guest can fill the named slots with cheap names, so the per-host
detail is a convenience; the totals beside it are exact.
"""

import json
import os
import time

# Twenty named hosts and an overflow bucket per map.
STATUS_TOP_N = 20

OTHER_KEY = "(other)"


class BoundedCounts:
    """A counter map keyed on a guest-chosen string that cannot grow past
    `top_n` named keys plus `(other)`. Not thread-safe; callers lock.
    """

    def __init__(self, top_n: int = STATUS_TOP_N):
        self._top_n = top_n
        self._counts: dict[str, int] = {}
        self._other = 0

    def add(self, key: str, n: int = 1) -> None:
        if key in self._counts:
            self._counts[key] += n
        elif len(self._counts) < self._top_n:
            self._counts[key] = n
        else:
            self._other += n

    @property
    def total(self) -> int:
        """Every event, named or overflowed. Exact."""
        return sum(self._counts.values()) + self._other

    def snapshot(self) -> dict:
        """The map as it goes into the status file, with `(other)` only when
        it is non-zero.
        """
        out = dict(self._counts)
        if self._other:
            out[OTHER_KEY] = self._other
        return out


def clear_status(path: str) -> None:
    """Remove one status file and any temp file left beside it.

    For whatever starts the workload to call at start: a socket-activated
    inspector writes nothing until the guest first dials, and until then the
    last instance's file would read as this one's. Never raises.
    """
    for candidate in (path, f"{path}.tmp"):
        try:
            os.unlink(candidate)
        except OSError:
            pass


def write_status(path: str, payload: dict) -> None:
    """Replace a status file atomically, stamping when it was written.

    `written_at` is what tells a process that died from one that is idle.
    Failures are the caller's to log. The file is 0600 whatever the umask:
    it names the hosts the workload reached.
    """
    body = dict(payload)
    body["written_at"] = time.time()
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    with open(fd, "w") as f:
        json.dump(body, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)
