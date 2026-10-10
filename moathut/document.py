"""The hut's copy of the policy document, and what `allow` writes into it.

`allow` only widens. A host `hosts` admits is left alone, since an entry
for it would restrict it to the entry; a host entries govern gets
another entry, since `hosts` is not consulted for it (POLICY.md, the
composition rule).
"""

import json

from moatery.inspect_document import (hostname_bad_character,
                                      normalize_hostname)


class AllowRefused(ValueError):
    """An allow that would narrow a host, or send a key further than it
    names."""


def host_name(text):
    """A host name as the lists match it, or raise: a pattern is the
    document's to hold, written with `moathut network-policy`."""
    host = normalize_hostname(text)
    if not host or hostname_bad_character(host):
        raise AllowRefused(f"{text!r} is not a host name; a pattern is "
                           "written with moathut network-policy NAME")
    return host


def allow(doc, policy, host, methods=(), paths=()):
    """The document with HOST allowed, or None if the policy allows what
    was asked already. `doc` is the parsed document and `policy` the
    same document loaded; `host` is a host_name."""
    methods = list(dict.fromkeys(m.upper() for m in methods))
    paths = list(dict.fromkeys(paths))
    for path in paths:
        if not path.startswith(("/", "*")):
            raise AllowRefused(f"--path {path!r} is matched against a "
                               "request's path, which begins with /")
    entry = {"host": host}
    if methods:
        entry["methods"] = methods
    if paths:
        entry["paths"] = paths
    doc = json.loads(json.dumps(doc))
    if policy.governs(host):
        if not (methods or paths):
            raise AllowRefused(
                f"{host} is governed by its policy entries, which hosts "
                "does not widen: give --method or --path")
        credential = policy.credential_for(host)
        if credential and not paths:
            raise AllowRefused(
                f"{host} is brokered with {credential}, and an entry "
                "without --path sends the key to every path")
        if entry in (doc.get("policy") or []):
            return None
        doc["policy"] = (doc.get("policy") or []) + [entry]
    elif policy.admits(host):
        return None
    elif methods or paths:
        doc["policy"] = (doc.get("policy") or []) + [entry]
    else:
        doc["hosts"] = (doc.get("hosts") or []) + [host]
    return doc


def dumps(doc):
    return json.dumps(doc, indent=2) + "\n"
