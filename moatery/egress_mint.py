"""
egress_mint -- minting a workload's egress CA once, and the leaf certificates
its inspector presents.

A mint is an openssl subprocess, since the stdlib cannot sign, and a cache
miss is guest-reachable because the guest picks the names. So there are two
bounded caches, a working set and a denial set that a flood of invented
names cannot evict the working set from, and a token bucket over all
minting. Each denial needs a leaf of its own: a shared one fails the
client's name check, and the guest sees a certificate error instead of the
403.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import subprocess
import tempfile
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import NamedTuple

from .inspect_document import normalize_hostname
from .egress_ca import (
    DENIAL_DIR_NAME, LEAF_DIR_NAME, LEAF_RENEW_WITHIN_SECONDS, LeafRefused,
    ca_cert_path, ca_key_path, ca_openssl_argv, leaf_openssl_argv, leaf_san,
)

# The working set, far above any guest's real destination count.
LEAF_CACHE_MAX = 1024

# The denial set. It must hold more entries than there are connections in
# flight: eviction unlinks a leaf's PEM, and the handshake opens it after
# the minter hands it over, so a flood of denials could otherwise delete a
# leaf a handshake is about to use. Twice the listener's MAX_CONNECTIONS;
# the mint tests assert it.
DENIAL_CACHE_MAX = 256

# The bucket: 256 tokens refilling at 1/s. A cold guest contacting fifty
# hosts spends fifty at once; a guest minting continuously gets one a second.
MINT_BUCKET_CAPACITY = 256
MINT_BUCKET_REFILL_PER_SECOND = 1.0

# How long an allowlisted mint waits for a token. A denial does not wait.
MINT_WAIT_SECONDS = 5.0


class MintThrottled(Exception):
    """The token bucket was empty. Carries which disposition was refused."""

    def __init__(self, name: str, *, denied: bool):
        self.name = name
        self.denied = denied
        super().__init__(
            f"mint rate limit reached for {name!r} "
            f"({'denied' if denied else 'allowlisted'})")


class MintFailed(Exception):
    """openssl refused to sign, with its own words in the message."""


def mint_ca(name: str, state_dir, *, now: float | None = None,
            runner=subprocess.run) -> bool:
    """Mint the workload's egress CA into `state_dir`, unless it is there.

    True if this call minted it, False if a key and a certificate were
    already present; those are left alone, since the guest's trust bundle
    was built from that certificate. Half a CA is refused, not repaired:
    which half to keep is the operator's call.
    """
    key, cert = ca_key_path(state_dir), ca_cert_path(state_dir)
    have_key, have_cert = key.exists(), cert.exists()
    if have_key and have_cert:
        return False
    if have_key or have_cert:
        present, missing = (key, cert) if have_key else (cert, key)
        raise MintFailed(
            f"{present} is there and {missing} is not; remove the one "
            f"that is there to mint a new CA, or restore the other")
    try:
        key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=key.parent) as tmp:
            staged_key = Path(tmp) / key.name
            staged_cert = Path(tmp) / cert.name
            try:
                argv = ca_openssl_argv(
                    name, staged_key, staged_cert,
                    now=time.time() if now is None else now)
            except ValueError as exc:
                raise MintFailed(str(exc)) from None
            try:
                result = runner(argv, capture_output=True, text=True,
                                timeout=60)
            except (OSError, subprocess.SubprocessError) as exc:
                raise MintFailed(f"could not run openssl: {exc}") from exc
            if result.returncode != 0:
                detail = ((result.stderr or "")
                          + (result.stdout or "")).strip()
                raise MintFailed(
                    f"openssl refused to mint the CA for {name!r}: {detail}")
            os.chmod(staged_key, 0o600)
            # The key first: a stop between the two leaves a key with no
            # certificate, which the next call refuses by name.
            os.replace(staged_key, key)
            os.replace(staged_cert, cert)
    except OSError as exc:
        raise MintFailed(
            f"could not write the CA into {key.parent}: {exc}") from exc
    return True


class Leaf(NamedTuple):
    """One minted leaf: a PEM holding the certificate and its key, and when
    it stops being usable. One file, so eviction is one unlink."""
    name: str
    path: Path
    not_after: float

    def due_for_renewal(self, now: float) -> bool:
        return now >= self.not_after - LEAF_RENEW_WITHIN_SECONDS


class TokenBucket:
    """A refilling bucket, thread-safe, with an optional bounded wait.
    Monotonic, so a clock stepped backwards does not freeze it."""

    def __init__(self, capacity: float = MINT_BUCKET_CAPACITY,
                 refill_per_second: float = MINT_BUCKET_REFILL_PER_SECOND,
                 *, clock=time.monotonic, sleep=time.sleep):
        self.capacity = float(capacity)
        self.refill_per_second = float(refill_per_second)
        self._clock = clock
        self._sleep = sleep
        self._tokens = float(capacity)
        self._last = clock()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self.capacity,
                           self._tokens + elapsed * self.refill_per_second)

    @property
    def tokens(self) -> float:
        with self._lock:
            self._refill_locked()
            return self._tokens

    def take(self) -> bool:
        """One token if there is one, without waiting."""
        with self._lock:
            self._refill_locked()
            if self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            return True

    def wait(self, timeout: float) -> bool:
        """One token, waiting up to `timeout` seconds for it."""
        deadline = self._clock() + timeout
        while True:
            if self.take():
                return True
            if self._clock() >= deadline:
                return False
            self._sleep(min(0.05, self.refill_per_second and
                            1.0 / self.refill_per_second or 0.05))


class LeafCache:
    """A bounded LRU of leaves, each a PEM in the cache's own directory.

    Two caches never share a directory: eviction unlinks files, and a flood
    of denials would otherwise delete the working set. The PEMs outlive a
    restart, so a socket-activated listener does not re-mint its working
    set each time it starts.
    """

    def __init__(self, capacity: int, directory: Path, issuer=None):
        self.capacity = capacity
        self.directory = Path(directory)
        # A callable giving the key id of the CA a leaf must chain to, or
        # None to adopt without asking. See _adopt.
        self._issuer = issuer
        self._entries: OrderedDict[str, Leaf] = OrderedDict()
        self._lock = threading.RLock()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._trim_directory()

    def _trim_directory(self) -> None:
        """Delete the oldest PEMs on disk down to `capacity`, since files a
        previous process evicted were never in this one's LRU."""
        try:
            pems = sorted(self.directory.glob("*.pem"),
                          key=lambda p: p.stat().st_mtime)
        except OSError:
            return
        for stale in pems[:max(0, len(pems) - self.capacity)]:
            stale.unlink(missing_ok=True)

    def path_for(self, name: str) -> Path:
        """Where `name`'s PEM lives: hashed, since the name is guest input
        and a listing should not show the guest's destinations."""
        digest = hashlib.sha256(name.encode()).hexdigest()
        return self.directory / f"{digest}.pem"

    def get(self, name: str, *, now: float) -> Leaf | None:
        """A usable leaf for `name`, or None. Renewal-due counts as a miss."""
        with self._lock:
            leaf = self._entries.get(name)
            if leaf is None:
                leaf = self._adopt(name, now=now)
                if leaf is None:
                    return None
            if leaf.due_for_renewal(now) or not leaf.path.exists():
                self._drop(name)
                return None
            self._entries.move_to_end(name)
            return leaf

    def _adopt(self, name: str, *, now: float) -> Leaf | None:
        """Take a PEM a previous process left, on a miss.

        Only a leaf the current CA signed, compared by key id: a CA minted
        again leaves leaves nothing trusts, under the same subject.
        """
        path = self.path_for(name)
        if not path.exists():
            return None
        not_after, authority = pem_leaf_facts(path)
        if not_after is None or (
                self._issuer is not None
                and (authority is None or authority != self._issuer())):
            path.unlink(missing_ok=True)
            return None
        leaf = Leaf(name=name, path=path, not_after=not_after)
        self._insert(leaf)
        return leaf

    def put(self, leaf: Leaf) -> None:
        with self._lock:
            self._insert(leaf)

    def _insert(self, leaf: Leaf) -> None:
        self._entries[leaf.name] = leaf
        self._entries.move_to_end(leaf.name)
        while len(self._entries) > self.capacity:
            _name, evicted = self._entries.popitem(last=False)
            evicted.path.unlink(missing_ok=True)

    def _drop(self, name: str) -> None:
        leaf = self._entries.pop(name, None)
        if leaf is not None:
            leaf.path.unlink(missing_ok=True)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __contains__(self, name: str) -> bool:
        with self._lock:
            return name in self._entries


def pem_fingerprint(path: Path) -> str | None:
    """The SHA-256 fingerprint of the first certificate in a PEM, or None.

    Spelled as `openssl x509 -fingerprint -sha256` prints it, and the one
    spelling anything comparing CAs should use.
    """
    try:
        text = path.read_text()
    except OSError:
        return None
    marker = "-----BEGIN CERTIFICATE-----"
    start = text.find(marker)
    end = text.find("-----END CERTIFICATE-----", start + 1)
    if start == -1 or end == -1:
        return None
    body = text[start + len(marker):end]
    try:
        der = base64.b64decode("".join(body.split()), validate=True)
    except (ValueError, binascii.Error):
        return None
    if not der:
        return None
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _key_id(text: str, extension: str) -> str | None:
    """The key id `openssl x509 -ext` printed under `extension`, or None.
    Older openssl prefixes an authority key id with `keyid:`."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith(extension) and i + 1 < len(lines):
            value = lines[i + 1].strip().removeprefix("keyid:")
            return value.upper() or None
    return None


def pem_leaf_facts(path: Path) -> tuple[float | None, str | None]:
    """(notAfter, authority key id) of the certificate in a PEM, either of
    them None where it cannot be read. One openssl call for both."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(path), "-noout", "-enddate",
             "-ext", "authorityKeyIdentifier"],
            capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, None
    if result.returncode != 0:
        return None, None
    first, _, _rest = result.stdout.partition("\n")
    return (_parse_not_after(first),
            _key_id(result.stdout, "X509v3 Authority Key Identifier"))


def pem_subject_key_id(path: Path) -> str | None:
    """The subject key id of the certificate in a PEM, or None."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(path), "-noout",
             "-ext", "subjectKeyIdentifier"],
            capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return _key_id(result.stdout, "X509v3 Subject Key Identifier")


def _parse_not_after(line: str) -> float | None:
    """`notAfter=...` as openssl prints it, as a unix timestamp."""
    _, _, when = line.strip().partition("=")
    try:
        import ssl
        return float(ssl.cert_time_to_seconds(when))
    except (ValueError, OSError):
        return None


def pem_not_after(path: Path) -> float | None:
    """The notAfter of the certificate in a PEM, as a unix timestamp, or
    None if it cannot be read, which the caller treats as not cached."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(path), "-noout", "-enddate"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return _parse_not_after(result.stdout)


class Minter:
    """Leaves for one workload, cached and rationed.

    A leaf is backdated an hour; a guest whose clock is further out rejects
    it, and that is for whatever owns the guest to repair.
    """

    def __init__(self, name: str, state_dir, *,
                 clock=time.time, runner=subprocess.run,
                 bucket: TokenBucket | None = None):
        self.name = name
        self.state_dir = Path(state_dir)
        self._clock = clock
        self._runner = runner
        self.bucket = bucket if bucket is not None else TokenBucket()
        self._ca_key_id = None
        self.working_set = LeafCache(
            LEAF_CACHE_MAX, self.state_dir / LEAF_DIR_NAME,
            issuer=self._issuer_key_id)
        self.denials = LeafCache(
            DENIAL_CACHE_MAX, self.state_dir / DENIAL_DIR_NAME,
            issuer=self._issuer_key_id)
        # The denied_* figures are subsets of mints and hits, not a second
        # dimension: a guest driving the minter shows up in them.
        self.stats = {
            "mints": 0, "denied_mints": 0,
            "hits": 0, "denied_hits": 0,
            "throttled": 0, "refused": 0, "failed": 0,
        }
        self._lock = threading.Lock()
        self._ca_identity = None

    def _issuer_key_id(self) -> str | None:
        """The CA's subject key id, read once: a new CA needs a new trust
        bundle in the guest, and a restart."""
        if self._ca_key_id is None:
            self._ca_key_id = pem_subject_key_id(ca_cert_path(self.state_dir))
        return self._ca_key_id

    def _bump(self, *names: str) -> None:
        """Add one to each named counter, in one critical section, so a
        reader never sees a total ahead of its subset."""
        with self._lock:
            for name in names:
                self.stats[name] += 1

    def leaf(self, server_name: str, *, denied: bool) -> Leaf:
        """A leaf for one exact name. Raises rather than returning a sentinel.

        On an empty bucket a denial fails at once, and an allowlisted name
        waits up to MINT_WAIT_SECONDS.
        """
        name = normalize_hostname(server_name)
        cache = self.denials if denied else self.working_set
        now = self._clock()

        cached = cache.get(name, now=now)
        if cached is not None:
            self._bump(*(("hits", "denied_hits") if denied else ("hits",)))
            return cached

        # The name is checked before a token is spent: a refusal runs no
        # openssl, and a guest sending refused names would otherwise empty
        # the bucket for allowlisted mints.
        try:
            leaf_san(name)
        except LeafRefused:
            self._bump("refused")
            raise

        if denied:
            if not self.bucket.take():
                self._bump("throttled")
                raise MintThrottled(name, denied=True)
        else:
            if not self.bucket.wait(MINT_WAIT_SECONDS):
                self._bump("throttled")
                raise MintThrottled(name, denied=False)

        leaf = self._mint(name, cache, denied=denied)
        cache.put(leaf)
        return leaf

    def ca_identity(self) -> dict:
        """The CA's fingerprint and notAfter, read once. Failures are None:
        this runs on the status path."""
        if self._ca_identity is None:
            cert = ca_cert_path(self.state_dir)
            self._ca_identity = {
                "sha256": pem_fingerprint(cert),
                "not_after": pem_not_after(cert),
            }
        return dict(self._ca_identity)

    def snapshot(self) -> dict:
        """Everything this minter reports, counters and live sizes together."""
        with self._lock:
            out = dict(self.stats)
        out["working_set"] = len(self.working_set)
        out["denials"] = len(self.denials)
        out["tokens"] = round(self.bucket.tokens, 2)
        out["ca"] = self.ca_identity()
        return out

    def _mint(self, name: str, cache: LeafCache, *, denied: bool) -> Leaf:
        """Sign one leaf and land it as a single PEM, atomically, from a
        temporary directory inside the cache's."""
        target = cache.path_for(name)
        argv_dir = cache.directory

        now = self._clock()
        # Every filesystem step is inside this, so an unwritable cache is a
        # MintFailed, named and counted, rather than an OSError the
        # connection handler swallows.
        try:
            with tempfile.TemporaryDirectory(dir=argv_dir) as tmp:
                key_path = Path(tmp) / "leaf.key"
                cert_path = Path(tmp) / "leaf.crt"
                argv = leaf_openssl_argv(
                    name, ca_key_path(self.state_dir),
                    ca_cert_path(self.state_dir),
                    key_path, cert_path, now=now)
                try:
                    result = self._runner(argv, capture_output=True, text=True,
                                          timeout=30)
                except (OSError, subprocess.SubprocessError) as exc:
                    self._bump("failed")
                    raise MintFailed(f"could not run openssl: {exc}") from exc
                if result.returncode != 0:
                    self._bump("failed")
                    detail = ((result.stderr or "")
                              + (result.stdout or "")).strip()
                    raise MintFailed(
                        f"openssl refused to mint a leaf for {name!r}: "
                        f"{detail}")
                staged = Path(tmp) / "leaf.pem"
                staged.write_text(cert_path.read_text() + key_path.read_text())
                os.chmod(staged, 0o600)
                os.replace(staged, target)
        except OSError as exc:
            self._bump("failed")
            raise MintFailed(
                f"could not write a leaf for {name!r} into {argv_dir}: "
                f"{exc}") from exc

        self._bump(*(("mints", "denied_mints") if denied else ("mints",)))
        not_after = pem_not_after(target)
        if not_after is None:
            target.unlink(missing_ok=True)
            self._bump("failed")
            raise MintFailed(f"minted leaf for {name!r} is unreadable")
        return Leaf(name=name, path=target, not_after=not_after)


__all__ = [
    "DENIAL_CACHE_MAX", "LEAF_CACHE_MAX",
    "MINT_BUCKET_CAPACITY", "MINT_BUCKET_REFILL_PER_SECOND",
    "MINT_WAIT_SECONDS", "Leaf", "LeafCache", "LeafRefused", "MintFailed",
    "MintThrottled", "Minter", "TokenBucket", "mint_ca",
]
