"""The counters a long-running inspector emits, and the file it emits them
into.

WHY THIS IS ITS OWN MODULE

Anything that reports on a workload's traffic needs the same two things: a
per-host map that a guest cannot grow without limit, and a status file
replaced atomically. Defined once so that two producers on one host (an
inspector and, say, a resolver) cannot end up with two definitions of
"bounded" -- and so that each writes its OWN file. `os.replace` on a shared
path has exactly one winner, whichever wrote last, with the other's figures
gone; the failure is silent and looks like a counter that does not move.

THE BOUND, AND WHAT IT HONESTLY IS

Every per-host figure is keyed on a string the GUEST chooses. Unbounded, a
guest touching a1.example.com ... a100000.example.com grows the status file
without limit and, through anything that exports it as metrics, produces a
cardinality explosion ON THE HOST -- a failure outside the workload that
caused it. So each map holds at most `top_n` named keys and everything else
lands in one `(other)` bucket.

`(other)` counts EVENTS, not hosts. "And 41,882 more hosts" cannot be
produced by a bounded structure: knowing how many DISTINCT hosts overflowed
means remembering which ones did, which is the unbounded set the bound
exists to avoid. An exact distinct count and a bound are not both available
here, and the bound is the one that protects the host.

Named keys are FIRST-SEEN, not busiest. Busiest-N is the more useful report
and needs full counts to compute, which is the same unbounded map again.
The consequence is worth stating because it is adversarial: a guest can
fill all `top_n` slots with cheap names and push its real traffic into
`(other)`. That does not hide the traffic -- `(other)` climbing IS the
signal, and the totals beside these maps are exact -- but it does mean the
per-host detail is a convenience for an operator reading a healthy
workload, and never the evidence on which a compromised one is judged.
"""

import json
import os
import time

# Twenty named hosts and an overflow bucket. Large enough that a real
# workload's list fits -- an agent VM's allowlist is a handful of names --
# and small enough that the exporter's label cardinality per workload is
# bounded by something an operator can hold in their head.
STATUS_TOP_N = 20

OTHER_KEY = "(other)"


class BoundedCounts:
    """A counter map keyed on a guest-chosen string that cannot grow past
    `top_n` named keys plus `(other)`.

    Not thread-safe on its own; the callers hold a lock around whole
    observations, because a status file that is internally inconsistent is
    worse than one written a tick later.
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
            # Once a key overflows it stays overflowed for the life of the
            # process, including on its second and later hits. That is what
            # makes this a fixed-size structure rather than one that merely
            # reports a fixed size.
            self._other += n

    @property
    def total(self) -> int:
        """Every event, named or overflowed. Exact, and the figure to trust."""
        return sum(self._counts.values()) + self._other

    def snapshot(self) -> dict:
        """The map as it goes into the status file.

        `(other)` appears only when it is non-zero: a bucket reading zero on
        every healthy workload trains an operator to skip the line, and this is
        the line that matters when it is not zero.
        """
        out = dict(self._counts)
        if self._other:
            out[OTHER_KEY] = self._other
        return out


def clear_status(path: str) -> None:
    """Remove one status file and any temp file left beside it.

    WHY THIS IS NEEDED AT ALL

    A status file in a directory that outlives the process outlives the
    instance that wrote it. The inspector is socket-activated -- it starts
    on the guest's first dial -- so between a workload start and the guest's
    first outbound anything, the previous instance's file is the one on
    disk, and it reads as this instance's, with counters for traffic that
    happened before the restart. `written_at` does not disambiguate it: a
    file from a previous run and a file from a process that has been idle
    since that moment look identical, because they are the same file.

    For whatever arms the workload to call at start, rather than at stop,
    because a stop is not guaranteed to run -- a host that loses power, or a
    service killed hard, leaves the file either way. Starting happens on
    every start by definition.

    Tolerant of everything: a missing file is the normal case on a first
    start, and a diagnostic that could not be cleared must never fail a
    workload's start.
    """
    for candidate in (path, f"{path}.tmp"):
        try:
            os.unlink(candidate)
        except OSError:
            pass


def write_status(path: str, payload: dict) -> None:
    """Replace a status file atomically, stamping when it was written.

    Replaced rather than truncated in place for the reason the policy documents
    are: a reader that arrives mid-write must see the previous complete file,
    not a half-written one. A reader runs at a moment nobody chose.

    `written_at` is not decoration. The ABSENCE of a status file means "this
    process has never served anything", which is the healthy state of a
    freshly started workload -- so a stale timestamp is the only way to tell a
    process that died from one that is quietly idle. Both look identical from
    the file's existence alone.

    Failures are swallowed by the CALLER, not here: a status write that cannot
    land must never take down a listener that is otherwise serving the guest
    correctly, and the caller is where the log line for that belongs.
    """
    body = dict(payload)
    body["written_at"] = time.time()
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(body, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)
