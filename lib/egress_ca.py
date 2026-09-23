#!/usr/bin/env python3
"""The per-workload egress CA, the leaves it signs, and where all of it lives.

Paths and openssl argv only; lib/egress_mint.py runs them. The directory
names are here because whatever manages the state directory from outside
has to name the same ones the minter creates.
"""

import ipaddress
import time
from pathlib import Path

from inspect_document import normalise_hostname


# --- The per-workload egress CA ---
#
# One per workload, made once and never churned, in the workload's state
# directory. Only that workload trusts it, so a stolen key impersonates
# sites to the workload itself.

CA_DIR_NAME = "ca"
CA_KEY_NAME = "egress-ca.key"
CA_CERT_NAME = "egress-ca.crt"


# The two leaf caches, beside the CA.
LEAF_DIR_NAME = "leaves"
DENIAL_DIR_NAME = "leaves-denied"


# Ten years. A CA is never rotated, since replacing one means
# re-provisioning the guest, so its validity bounds the workload's life;
# the certificate's notAfter is reported, so the date is visible.
CA_VALIDITY_DAYS = 3650


# notBefore is backdated an hour, so a guest clock up to an hour behind,
# a paused VM's included, still accepts a fresh leaf.
CA_BACKDATE_SECONDS = 3600


def ca_dir(state_dir) -> Path:
    """Where this workload's egress CA lives, given its state directory."""
    return Path(state_dir) / CA_DIR_NAME


def ca_key_path(state_dir) -> Path:
    return ca_dir(state_dir) / CA_KEY_NAME


def ca_cert_path(state_dir) -> Path:
    return ca_dir(state_dir) / CA_CERT_NAME


def leaf_dir(state_dir) -> Path:
    """Where the working set of minted leaves lives."""
    return Path(state_dir) / LEAF_DIR_NAME


def denial_dir(state_dir) -> Path:
    """Where leaves minted under a refusal live -- a sibling of the working
    set, not a subdirectory, so a `rm -rf` of one cannot take the other."""
    return Path(state_dir) / DENIAL_DIR_NAME


def ca_subject(name: str) -> str:
    """The CA's subject, naming the workload, so a certificate error inside
    it says which CA it came from.
    """
    return f"/CN=customs egress CA ({name})"


def ca_openssl_argv(name: str, key_path, cert_path, *,
                    now: float) -> list[str]:
    """One `openssl req -x509` invocation that mints the CA.

    The three extensions are required: without a Subject Key Identifier and
    keyUsage, Python's ssl rejects the chain where curl, Go and Node accept
    it. `-not_before` needs OpenSSL 3.5. ECDSA P-256, as the leaves are.
    """
    not_before = time.strftime(
        "%Y%m%d%H%M%SZ", time.gmtime(now - CA_BACKDATE_SECONDS))
    return [
        "openssl", "req", "-x509",
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-noenc",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(CA_VALIDITY_DAYS),
        "-not_before", not_before,
        "-subj", ca_subject(name),
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ]


# --- Leaves ---
#
# What the CA above signs, one per exact name the guest asks for.

# Thirty days: nothing renews a leaf except the cache re-minting it, and a
# leaked one is valid for one host.
LEAF_VALIDITY_DAYS = 30


# Re-mint once a leaf is within a day of notAfter.
LEAF_RENEW_WITHIN_SECONDS = 86400


class LeafRefused(ValueError):
    """A name that will not be minted for, with the reason in the message.

    Raised before openssl: the name goes into an `-addext` argument, and a
    comma in it would add extensions of the guest's choosing.
    """


# The longest a DNS name may be, and the longest one label may be (RFC 1035).
LEAF_NAME_MAX = 253
LEAF_LABEL_MAX = 63


_LEAF_LABEL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789-_")


def leaf_san(name: str) -> str:
    """The subjectAltName value for one name, or raise LeafRefused.

    An allowlist of characters, not a denylist: what openssl's extension
    parser treats as special is openssl's to change. `_` is allowed,
    against RFC 1035, because real service names use it. An IP literal gets
    an `IP:` SAN, since a `DNS:` one holding an address matches nothing.
    """
    name = normalise_hostname(name)
    if not name:
        raise LeafRefused("empty name")

    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        address = None
    if address is not None:
        # A scoped address is refused: ip_address keeps whatever follows `%`,
        # commas included.
        if getattr(address, "scope_id", None):
            raise LeafRefused(f"a scoped address in {name!r}")
        return f"IP:{address}"

    if len(name) > LEAF_NAME_MAX:
        raise LeafRefused(f"name longer than {LEAF_NAME_MAX} characters")
    labels = name.split(".")
    for label in labels:
        if not label:
            raise LeafRefused(f"empty label in {name!r}")
        if len(label) > LEAF_LABEL_MAX:
            raise LeafRefused(f"label longer than {LEAF_LABEL_MAX} "
                              f"characters in {name!r}")
        bad = set(label) - _LEAF_LABEL_CHARS
        if bad:
            raise LeafRefused(
                f"character {sorted(bad)[0]!r} not permitted in a name")
    return f"DNS:{name}"


def leaf_openssl_argv(name: str, ca_key, ca_cert,
                         key_path, cert_path, *, now: float) -> list[str]:
    """One `openssl req -x509 -CA` invocation that mints a leaf for `name`.

    The subject is empty, so RFC 5280 requires a critical SAN, and Python
    rejects the chain without it. The SAN is the exact name asked for,
    never the pattern that matched it.
    """
    not_before = time.strftime(
        "%Y%m%d%H%M%SZ", time.gmtime(now - CA_BACKDATE_SECONDS))
    return [
        "openssl", "req", "-x509",
        "-CA", str(ca_cert),
        "-CAkey", str(ca_key),
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-noenc",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(LEAF_VALIDITY_DAYS),
        "-not_before", not_before,
        "-subj", "/",
        "-addext", f"subjectAltName=critical,{leaf_san(name)}",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", "subjectKeyIdentifier=hash",
        "-addext", "authorityKeyIdentifier=keyid",
    ]
