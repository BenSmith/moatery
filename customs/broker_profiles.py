"""What the shipped broker makes of its command line at startup.

`build_profiles` resolves each `--host HOST=CREDENTIAL` against the material
that credential id names and the flags describing it, into a table keyed by
Host. `normalise_host` is the one spelling of a Host the table is keyed by
and the server looks up. There is no config file: every value is on the
unit's ExecStart= line, and the material arrives by LoadCredentialEncrypted=.
tests/test_closure.py holds the flag set this reads.
"""

import dataclasses
import os
from pathlib import Path

# The auth convention for a credential whose flags name none: Anthropic's.
BROKER_DEFAULT_AUTH_HEADER = "x-api-key"
BROKER_DEFAULT_AUTH_FORMAT = "{secret}"


class BrokerConfigError(ValueError):
    """The command line, or the credential it names, cannot be used. The
    program turns it into an exit."""


# The upstream is https://<host> and nothing else, so the port is not a
# flag.
UPSTREAM_PORT = 443


@dataclasses.dataclass(frozen=True)
class Profile:
    """Everything a request needs, resolved per Host.

    `auth_value` is rendered once at start, so a bad --auth-format is a
    refusal to start rather than a failure on every request.
    """
    name: str
    host: str
    port: int
    auth_header: str
    auth_format: str
    secret: str
    auth_value: str


def normalise_host(value):
    """One `Host` header or flag key as the string the table is keyed by.

    Lowercased, port stripped, trailing root dot stripped: `API.GitHub.com`,
    `api.github.com:443` and `api.github.com.` are one host. None for
    anything that is not a usable host, which is a refusal and never a
    fallback, since the profile is selected by this value.
    """
    if not isinstance(value, str):
        return None
    host = value.strip().lower()
    if host.startswith("["):
        # A bracketed IPv6 literal, possibly with a port, kept whole so it
        # cannot be mangled into another entry's key.
        end = host.find("]")
        if end == -1:
            return None
        host = host[:end + 1]
    elif ":" in host:
        host = host.split(":", 1)[0]
    host = host.rstrip(".")
    # A space or a quote would forge a field of the `host=` refusal line.
    if not set(host) <= (_LITERAL_CHARS if host.startswith("[")
                         else _HOST_CHARS):
        return None
    return host or None


# What normalise_host lets through: a DNS name or an IPv4 literal, and the
# inside of a bracketed IPv6 one.
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_.")
_LITERAL_CHARS = frozenset("0123456789abcdef:.[]")


# RFC 9110 §5.6.2 tchar: what a header NAME may be spelled with.
_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _control_character(text):
    """The first character no header value may carry, or None. Tab is
    allowed."""
    for ch in text:
        if ch != "\t" and (ch < " " or ch == "\x7f"):
            return ch
    return None


def split_pair(value, flag):
    """(key, value) of one `KEY=VALUE` flag argument.

    Split on the first `=`, so a value may carry one. No `=` is refused
    rather than read as an empty value.
    """
    key, sep, val = value.partition("=")
    if not sep or not key:
        raise BrokerConfigError(f"{flag} takes KEY=VALUE, got {value!r}")
    return key, val


# The value form that binds a filesystem socket instead of an address, and
# the longest path one can name: sun_path is 108 bytes with its NUL.
UNIX_PREFIX = "unix:"
UNIX_PATH_MAX = 107


def listen_endpoint(value):
    """(address, port) of the `--listen` flag, or the path of `unix:PATH`.

    Required, with no default: an instance binds its own workload's address,
    and a shared default would put every broker where every inspector dials.
    An any-address bind is refused by name. `unix:PATH` is for a broker
    sharing a network namespace with its workload: the path is kept from
    the workload by the mount namespace. It is absolute, and never
    abstract, since an abstract name lives in the shared network namespace.
    """
    if value.startswith(UNIX_PREFIX):
        return _unix_path(value)
    address, sep, port = value.rpartition(":")
    if not sep or not address:
        raise BrokerConfigError(f"--listen takes ADDRESS:PORT, got {value!r}")
    if address in ("0.0.0.0", "::", "*", "[::]"):
        raise BrokerConfigError(
            f"--listen {value!r} binds every address on the host, including "
            f"the ones other workloads' brokers listen on. Bind this "
            f"workload's own address alone")
    try:
        port = int(port)
    except ValueError:
        raise BrokerConfigError(
            f"--listen {value!r}: the port is not a number")
    if not 0 <= port <= 65535:
        raise BrokerConfigError(
            f"--listen {value!r}: the port is out of range")
    return address, port


def _unix_path(value):
    path = value[len(UNIX_PREFIX):]
    if not path.startswith("/"):
        raise BrokerConfigError(
            f"--listen {value!r}: the socket path must be absolute, and "
            "never an abstract name")
    if "\0" in path:
        raise BrokerConfigError(
            f"--listen {value!r}: the socket path holds a NUL")
    if len(path.encode()) > UNIX_PATH_MAX:
        raise BrokerConfigError(
            f"--listen {value!r}: the socket path is longer than "
            f"{UNIX_PATH_MAX} bytes")
    return path


def _by_credential(values, flag):
    """{credential id: value} for one repeatable CREDENTIAL=VALUE flag. A
    credential given twice is refused, not last-wins."""
    table = {}
    for raw in values:
        cred_id, value = split_pair(raw, flag)
        if cred_id in table:
            raise BrokerConfigError(f"{flag} {cred_id}=... is given twice")
        table[cred_id] = value
    return table


def build_profiles(name, hosts, placeholders=(), auth_headers=(),
                   auth_formats=(), load=None):
    """Resolve the per-Host profile table from the flags, as given.

    `hosts` is every `--host HOST=CREDENTIAL`, in order; the other three are
    the repeatable `CREDENTIAL=VALUE` flags; `name` is the label profiles
    and log lines carry. There is no default entry: a Host with no flag gets
    nothing, so the Host a request carries selects a row and supplies
    nothing.

    Returns {host: Profile}, the host through normalise_host.
    """
    from_env = load is None and not os.environ.get("CREDENTIALS_DIRECTORY")
    load = load or load_credential
    if not hosts:
        raise BrokerConfigError(
            "no --host HOST=CREDENTIAL flags, so this broker holds "
            "credentials for nothing and would refuse every request it "
            "received")
    placeholders = _by_credential(placeholders, "--placeholder")
    auth_headers = _by_credential(auth_headers, "--auth-header")
    auth_formats = _by_credential(auth_formats, "--auth-format")

    secrets = {}
    profiles = {}
    for raw in hosts:
        raw_host, cred_id = split_pair(raw, "--host")
        where = f"--host {raw}"
        host = normalise_host(raw_host)
        if host is None:
            raise BrokerConfigError(
                f"{where}: {raw_host!r} is not a usable Host")
        if host in profiles:
            raise BrokerConfigError(
                f"{where}: {host!r} is already configured under a different "
                f"spelling; hosts are compared lowercased and without a port")
        if not cred_id:
            raise BrokerConfigError(
                f"{where}: no credential. A host with no credential is a "
                f"host the broker would forward for while attaching nothing")
        if cred_id not in secrets:
            secrets[cred_id] = load(cred_id)
        placeholder = placeholders.get(cred_id)
        if placeholder and placeholder == secrets[cred_id]:
            # The real key pasted where the placeholder goes, which is plain
            # configuration. Compared against the decrypted material.
            raise BrokerConfigError(
                f"{where}: the placeholder for {cred_id!r} is byte-identical "
                f"to the decrypted credential. The placeholder is the fiction "
                f"the guest holds and lives in plain-text configuration; if "
                f"it equals the real key then the real key is there too. "
                f"Rotate the credential, then put a plausible fake of the "
                f"same shape here")
        auth_format = auth_formats.get(cred_id, BROKER_DEFAULT_AUTH_FORMAT)
        try:
            auth_value = auth_format.format(secret=secrets[cred_id])
        except (KeyError, IndexError, ValueError) as exc:
            # The format is not echoed: a wrong one may hold part of the
            # secret.
            raise BrokerConfigError(
                f"--auth-format {cred_id}=... is not a usable format string "
                f"({type(exc).__name__}); it takes exactly {{secret}}")
        # Checked at start: http.client refuses a line break in a header by
        # raising with the value in its message, which would put the
        # credential in the journal. Neither message names the value.
        auth_header = auth_headers.get(cred_id, BROKER_DEFAULT_AUTH_HEADER)
        if not auth_header or any(c not in _TOKEN_CHARS for c in auth_header):
            raise BrokerConfigError(
                f"--auth-header {cred_id}={auth_header!r} is not a header "
                f"name")
        bad = _control_character(auth_value)
        if bad is not None:
            raise BrokerConfigError(
                f"{where}: the {auth_header} value for {cred_id!r} holds "
                f"U+{ord(bad):04X}, which no header can carry. The "
                f"credential file has more than one line, or the "
                f"--auth-format does; neither is shown here")
        profiles[host] = Profile(
            name=f"{name}/{host}",
            host=host,
            port=UPSTREAM_PORT,
            auth_header=auth_header,
            auth_format=auth_format,
            secret=secrets[cred_id],
            auth_value=auth_value,
        )

    # CUSTOMS_BROKER_SECRET is one value, and two credential ids under it
    # would send one provider's key to the other's host.
    if from_env and len(secrets) > 1:
        raise BrokerConfigError(
            f"--host names {len(secrets)} credentials "
            f"({', '.join(sorted(secrets))}) and $CREDENTIALS_DIRECTORY is "
            f"not set: CUSTOMS_BROKER_SECRET is one value, and every one of "
            f"them would be sent that value. Run under systemd with "
            f"LoadCredentialEncrypted=, or name one credential")

    # A credential described but never selected may have been meant for a
    # host misspelled elsewhere.
    for flag, table in (("--placeholder", placeholders),
                        ("--auth-header", auth_headers),
                        ("--auth-format", auth_formats)):
        unselected = sorted(set(table) - set(secrets))
        if unselected:
            raise BrokerConfigError(
                f"{flag} names {', '.join(unselected)}, which no --host "
                f"selects")
    return profiles


def load_credential(name):
    """Read the secret from the systemd credentials directory.

    The environment fallback is for local development, and for one
    credential only; build_profiles refuses a second.
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds_dir:
        try:
            secret = Path(creds_dir, name).read_text().strip()
        except OSError as exc:
            raise BrokerConfigError(
                f"credential {name!r} is not in $CREDENTIALS_DIRECTORY "
                f"({exc.strerror}); the unit's LoadCredentialEncrypted= "
                f"lines and its --host flags disagree")
        if not secret:
            raise BrokerConfigError(f"credential '{name}' is empty")
        return secret
    env = os.environ.get("CUSTOMS_BROKER_SECRET")
    if env:
        return env.strip()
    raise BrokerConfigError(
        "no credential: run under systemd with LoadCredentialEncrypted=, "
        "or set CUSTOMS_BROKER_SECRET for local testing")
