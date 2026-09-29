"""Credentials: each sealed once to this user and host, and held by the
broker of every box whose policy names it.

A credential's hosts are the most it is sent to. A box's broker holds
it for those of them the box's policy brokers with it, so an edited
policy cannot send a key anywhere its `credential add` did not name.
"""

import json
import re
import secrets
from typing import NamedTuple

from customs.broker_profiles import (
    BrokerConfigError, build_profiles, normalise_host)
from customs.inspect_document import hostname_match

from .paths import described, valid_name

_VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class CredentialError(ValueError):
    """A credential, or a policy's use of one, refused, with the reason."""


class Credential(NamedTuple):
    id: str
    hosts: tuple
    env: str
    auth_header: str
    auth_format: str
    placeholder: str

    def to_json(self):
        doc = self._asdict()
        del doc["id"]
        doc["hosts"] = list(self.hosts)
        return json.dumps(doc, indent=2) + "\n"

    @classmethod
    def from_json(cls, credential, text):
        doc = json.loads(text)
        doc["hosts"] = tuple(doc["hosts"])
        return cls(id=credential, **doc)


class Broker(NamedTuple):
    """What a box's broker holds: the credential each host it serves is
    sent, and those credentials, in the order the policy names them."""
    hosts: tuple
    credentials: tuple


def placeholder():
    return f"customs-placeholder-{secrets.token_hex(16)}"


def describe(credential, hosts, env, auth_header, auth_format, fiction,
             secret, *, reserved):
    """The credential, checked as its broker will check it, with the
    secret it will read."""
    if not valid_name(credential):
        raise CredentialError(f"{credential!r}: a credential's id is "
                              "lowercase letters, digits and inner "
                              "dashes, 48 at most")
    named = []
    for host in hosts:
        normal = normalise_host(host)
        if normal is None or normal.startswith("["):
            raise CredentialError(f"--host {host!r} is not a host name")
        if normal not in named:
            named.append(normal)
    if not named:
        raise CredentialError("a credential needs a --host")
    if not _VARIABLE.fullmatch(env) or env in reserved:
        raise CredentialError(f"--env {env!r} is not a variable a box's "
                              "credential may set")
    if "{secret}" not in auth_format:
        raise CredentialError(f"--auth-format {auth_format!r} has no "
                              "{secret}")
    if not secret:
        raise CredentialError("the secret is empty")
    try:
        build_profiles(credential, [f"{h}={credential}" for h in named],
                       [f"{credential}={fiction}"],
                       [f"{credential}={auth_header}"],
                       [f"{credential}={auth_format}"],
                       load=lambda _: secret)
    except BrokerConfigError as exc:
        raise CredentialError(str(exc)) from None
    return Credential(credential, tuple(named), env, auth_header,
                      auth_format, fiction)


def read(dirs, credential):
    if not valid_name(credential):
        raise CredentialError(f"{credential!r} is not a credential's id")
    try:
        text = described(dirs, credential).read_text()
    except FileNotFoundError:
        raise CredentialError(
            f"no credential {credential}: customs-box credential add "
            f"{credential} --host HOST --env VARIABLE") from None
    return Credential.from_json(credential, text)


def brokering(policy, load):
    """The broker a box with this policy has, or None if it names no
    credential. `load` gives a credential by its id, or raises."""
    named = list(dict.fromkeys(e.credential for e in policy.policy
                               if e.credential))
    if not named:
        return None
    held = {credential: load(credential) for credential in named}
    for entry in policy.policy:
        if entry.credential and not any(
                hostname_match(host, (entry.host,))
                for host in held[entry.credential].hosts):
            raise CredentialError(
                f"the entry for {entry.host} names {entry.credential}, "
                f"a credential for {', '.join(held[entry.credential].hosts)}"
                " only")
    # The inspector's own choice of credential for a host, among the hosts
    # each credential names.
    hosts = tuple((host, credential) for credential in named
                  for host in held[credential].hosts
                  if policy.credential_for(host) == credential)
    served = {credential for _, credential in hosts}
    for credential in named:
        if credential not in served:
            raise CredentialError(
                f"{credential} is named, but an earlier entry brokers each "
                "of its hosts with another credential")
    set_by = {}
    for credential in named:
        env = held[credential].env
        if env in set_by:
            raise CredentialError(f"{set_by[env]} and {credential} both "
                                  f"set {env}")
        set_by[env] = credential
    return Broker(hosts, tuple(held[c] for c in named))
