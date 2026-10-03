"""The inspector's policy document, rendered by hand for the tests.

moatery ships the READER of the document (moatery/inspect_policy.py) and not a
writer: whatever configures a workload renders one, in whatever grammar it
has. The listener's tests still need a writer to test the reader against
-- a listener reading a key nothing writes is a policy that loads clean and
authorises nothing -- so this is one, taking the same shape of input the
tests were written for: a network table with `hosts`, `tls`, and
`internal`/`splice` as lists of `{"host": ..., "reason": ...}` tables, and
`policy` as a list of entry tables. The table's `internal` is rendered as
the document's `internal_expected`, the key the reader takes.

What it normalises is what the document's vocabulary (moatery/inspect_document)
says a writer normalises: `methods` uppercased, `methods` and `paths` null
where absent and never an empty list in their place, and `credential`
carried only on the entries that set one.
"""

from moatery.inspect_document import TLS_DEFAULT


def _hosts_of(net, key):
    entries = net.get(key, [])
    if not isinstance(entries, list):
        return []
    return [e["host"].strip() for e in entries
            if isinstance(e, dict) and isinstance(e.get("host"), str)
            and e["host"].strip()]


def _list(value, *, upper=False):
    if value is None:
        return None
    if not isinstance(value, list):
        return []
    return [item.upper() if upper else item
            for item in value if isinstance(item, str)]


def _entries(net):
    raw = net.get("policy", [])
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        host = item.get("host")
        if not isinstance(host, str) or not host.strip():
            continue
        entry = {"host": host.strip(),
                 "methods": _list(item.get("methods"), upper=True),
                 "paths": _list(item.get("paths"))}
        credential = item.get("credential")
        if isinstance(credential, str) and credential.strip():
            entry["credential"] = credential.strip()
        out.append(entry)
    return out


def policy_document(net: dict) -> dict:
    """One policy document, as a writer would render it from `net`."""
    hosts = net.get("hosts", [])
    return {
        "tls": net.get("tls", TLS_DEFAULT),
        "hosts": list(hosts) if isinstance(hosts, list) else [],
        "internal_expected": _hosts_of(net, "internal"),
        "splice": _hosts_of(net, "splice"),
        "policy": _entries(net),
    }
