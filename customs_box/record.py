"""Reading a box's record: a line as a person reads it, the record
followed as it is written, and the refusals the box's policy still
makes."""

import json
import os
import time
from collections import Counter

from customs.egress_record import DROP_NOT_ALLOWLISTED, DROP_NOT_PERMITTED

# How far back the first lines are looked for: the record is capped at
# 512 MiB, and a line is under a kilobyte.
_TAIL_BYTES = 256 * 1024


def lines(path):
    """The record's lines, parsed; a line being written is skipped."""
    try:
        handle = open(path, "rb")
    except FileNotFoundError:
        return
    with handle:
        for raw in handle:
            doc = _parse(raw)
            if doc is not None:
                yield doc


def _parse(raw):
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def format_line(doc):
    status = doc.get("status")
    what = doc.get("method") or doc.get("mode") or "-"
    where = (doc.get("host") or "-") + (doc.get("path") or "")
    text = (f"{doc.get('ts') or '-'}  {doc.get('decision') or '-':<7} "
            f"{'-' if status is None else status:>3}  {what:<7} {where}")
    if doc.get("reason"):
        text += f"  ({doc['reason']})"
    if doc.get("credential"):
        text += f"  [{doc['credential']}]"
    return text


def follow(path, write, *, last=20, pause=time.sleep, interval=0.5):
    """Write the record's last lines, then each line as it is written,
    until interrupted. A record rotated away is followed into the new
    one from its start."""
    handle, inode, partial, first = None, None, b"", True
    try:
        while True:
            if handle is None:
                try:
                    handle = open(path, "rb")
                except FileNotFoundError:
                    first = False
                    pause(interval)
                    continue
                inode, partial = os.fstat(handle.fileno()).st_ino, b""
                if first:
                    for doc in _tail(handle, last):
                        write(format_line(doc))
                    first = False
            chunk = handle.read()
            if chunk:
                *complete, partial = (partial + chunk).split(b"\n")
                for raw in complete:
                    doc = _parse(raw)
                    if doc is not None:
                        write(format_line(doc))
                continue
            try:
                now = os.stat(path)
            except FileNotFoundError:
                now = None
            if (now is None or now.st_ino != inode
                    or now.st_size < handle.tell()):
                handle.close()
                handle = None
                continue
            pause(interval)
    finally:
        if handle is not None:
            handle.close()


def _tail(handle, count):
    size = os.fstat(handle.fileno()).st_size
    start = max(0, size - _TAIL_BYTES)
    handle.seek(start)
    raws = handle.read().split(b"\n")
    # The first piece is a line's end unless the read began at the start,
    # and the last is empty or a line being written.
    raws = raws[(1 if start else 0):-1]
    parsed = [doc for doc in map(_parse, raws) if doc is not None]
    return parsed[-count:] if count else []


def refusals(docs, policy):
    """(count, host, reason, request) for each refusal in the record that
    the policy would still make, the most frequent first. `request` is
    the method and path of a request the policy's entries refused, and
    empty for every other reason."""
    counts = Counter()
    for doc in docs:
        if doc.get("decision") != "drop":
            continue
        host, reason = doc.get("host"), doc.get("reason") or "-"
        method, path = doc.get("method"), doc.get("path")
        request = ""
        if reason == DROP_NOT_ALLOWLISTED:
            if host and policy.admits(host):
                continue
        elif reason == DROP_NOT_PERMITTED:
            if host and method and path is not None and policy.permits(
                    host, method, path):
                continue
            request = f"{method or '-'} {path or '-'}"
        counts[(host or "-", reason, request)] += 1
    return sorted(((n, *key) for key, n in counts.items()),
                  key=lambda row: (-row[0], row[1:]))


def unlisted(status_path, policy):
    """The names the responder was asked for that no list admitted, with
    their counts, less those the policy admits now; empty if it has
    written no status."""
    try:
        doc = json.loads(status_path.read_text())
    except (OSError, ValueError):
        return []
    names = doc.get("unlisted_names") if isinstance(doc, dict) else None
    if not isinstance(names, dict):
        return []
    return sorted(((n, name) for name, n in names.items()
                   if isinstance(n, int) and not policy.admits(name)),
                  key=lambda row: (-row[0], row[1]))
