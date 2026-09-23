"""inspect_counters: what the egress inspector reports about itself.

The writer of the `--status` file, which is exactly `Counters.snapshot()`.
`egress_status` holds the bounded per-host map and the atomic replace.
"""

import threading

from inspect_document import TLS_DEFAULT
from egress_record import (
    DROP_INTERNAL, DROP_REASONS, DROP_UNCLASSIFIED, PER_HOST_REASONS,
)
from egress_status import STATUS_TOP_N, BoundedCounts
from tls_hello import TLS_EXT_ECH

class Counters:
    """What the listener reports, and the only place any of it is defined.

    `ech_seen` counts the encrypted_client_hello extension wherever it
    appears, which GREASE dominates, so it measures capability. `ech_alarm`
    counts the extension on a hello whose name matched no list, which is
    real ECH reaching for somewhere policy refuses.

    `dispositions` is not one unit: a TLS decision is per connection
    (`spliced`, `terminated`) and a cleartext or terminated one per request
    (`forwarded`); `dropped` is whichever was refused. `drop_reasons` sums
    to `dropped` exactly. `bumped` is how a refusal was delivered, not a
    decision, so it stands outside `dispositions`.

    The per-host maps are bounded, since their keys can come from the guest;
    `per_host_totals` stays exact.
    """

    def __init__(self, policy=None, top_n=STATUS_TOP_N):
        self._lock = threading.Lock()
        self.dispositions = {"spliced": 0, "terminated": 0, "forwarded": 0,
                             "dropped": 0}
        self.bumped = 0
        # Records the per-request sink could not take. The warning is logged
        # once; this is what shows the record is incomplete.
        self.record_failures = 0
        # h2 sessions, whose requests are not in the record: nothing in them
        # was decoded.
        self.h2_unrecorded = 0
        # Connections admitted whose caller the lookup could not name.
        self.caller_unresolved = 0
        # Pre-seeded, so an absent reason and a zero one look the same.
        self.drop_reasons = {reason: 0 for reason in DROP_REASONS}
        self._unclassified = 0
        self.ech_seen = 0
        self.ech_alarm = 0
        self.per_host = {reason: BoundedCounts(top_n)
                         for reason in PER_HOST_REASONS}
        # Brokered requests, by host and by credential name, never the
        # material: this process has never seen it.
        self.credentialed = 0
        self.credentialed_hosts = BoundedCounts(top_n)
        self.per_credential = BoundedCounts(top_n)
        # Brokered requests the origin answered 401 or 403: every layer of
        # ours succeeded and the provider still said no.
        self.credential_unauthorized = 0
        # The per-host DROP_INTERNAL figure, under the key the status
        # document names it by.
        self.internal_refusals = self.per_host[DROP_INTERNAL]
        # Every list as loaded, which is what this process enforces whatever
        # the file now says.
        self.lists = {
            "tls": policy.tls if policy else TLS_DEFAULT,
            "hosts": list(policy.hosts) if policy else [],
            "internal": list(policy.internal) if policy else [],
            "splice": list(policy.splice) if policy else [],
            "http2": list(policy.http2) if policy else [],
            "policy": [
                {"host": e.host,
                 "methods": None if e.methods is None else list(e.methods),
                 "paths": None if e.paths is None else list(e.paths),
                 "credential": e.credential}
                for e in policy.policy
            ] if policy else [],
        }

    def record_hello(self, hello, on_a_list: bool) -> None:
        """The ECH tripwire, once per readable ClientHello. `on_a_list` is
        the decision already taken, not matched again."""
        if TLS_EXT_ECH not in hello.extensions:
            return
        with self._lock:
            self.ech_seen += 1
            if not on_a_list:
                self.ech_alarm += 1

    def record_splice(self) -> None:
        with self._lock:
            self.dispositions["spliced"] += 1

    def record_termination(self) -> None:
        """One connection whose guest handshake we completed and then
        served."""
        with self._lock:
            self.dispositions["terminated"] += 1

    def record_write_failure(self) -> None:
        """One record the sink refused: RequestLog's failure callback."""
        with self._lock:
            self.record_failures += 1

    def record_caller_unresolved(self) -> None:
        """One connection admitted without naming its caller."""
        with self._lock:
            self.caller_unresolved += 1

    def record_h2_unrecorded(self) -> None:
        """One h2 session whose requests this process never decoded."""
        with self._lock:
            self.h2_unrecorded += 1

    def record_bump(self) -> None:
        """One handshake completed to deliver a refusal; the refusal itself
        is counted by record_drop."""
        with self._lock:
            self.bumped += 1

    def record_forward(self) -> None:
        with self._lock:
            self.dispositions["forwarded"] += 1

    def record_drop(self, reason: str, host: str = None) -> None:
        """One refused connection or request, by reason, spelled as the
        journal spells it."""
        with self._lock:
            self.dispositions["dropped"] += 1
            if reason in self.drop_reasons:
                self.drop_reasons[reason] += 1
            else:
                # Counted, so drop_reasons still sums to dropped.
                self._unclassified += 1
            if host and reason in self.per_host:
                self.per_host[reason].add(host)

    def record_credentialed(self, host: str, credential: str) -> None:
        """One request sent to the broker, counted once its dial succeeds."""
        with self._lock:
            self.credentialed += 1
            self.credentialed_hosts.add(host)
            self.per_credential.add(credential)

    def record_credential_unauthorized(self) -> None:
        """One brokered request the origin answered 401 or 403."""
        with self._lock:
            self.credential_unauthorized += 1

    def snapshot(self, *, open_now: int, refused: int) -> dict:
        with self._lock:
            reasons = dict(self.drop_reasons)
            if self._unclassified:
                reasons[DROP_UNCLASSIFIED] = self._unclassified
            return {
                "dispositions": dict(self.dispositions),
                "drop_reasons": reasons,
                "ech": {"seen": self.ech_seen, "alarm": self.ech_alarm},
                "bumped": self.bumped,
                "record_failures": self.record_failures,
                "h2_unrecorded": self.h2_unrecorded,
                "caller_unresolved": self.caller_unresolved,
                "internal_refusals": self.internal_refusals.snapshot(),
                "internal_refusals_total": self.internal_refusals.total,
                "per_host": {reason: counts.snapshot()
                             for reason, counts in self.per_host.items()},
                "per_host_totals": {reason: counts.total
                                    for reason, counts in
                                    self.per_host.items()},
                "credentialed": self.credentialed,
                "credentialed_hosts": self.credentialed_hosts.snapshot(),
                "per_credential": self.per_credential.snapshot(),
                "credential_unauthorized": self.credential_unauthorized,
                "concurrency": {"open": open_now, "refused": refused},
                "lists": dict(self.lists),
            }
