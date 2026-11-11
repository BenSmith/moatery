# Examples: the host placement as user units

Units for a rootless podman container inspected by moatery, its
inspector, broker and responder running as the user on the host
([DESIGN.md](../docs/DESIGN.md), "Host"). They assume the RPM is
installed (`just rpm` builds it): the programs in
`/usr/libexec/moatery/`, the `moatery` package where Python finds it,
and these files in `/usr/share/doc/moatery/examples/`. The commands
below are run from that directory, or from `examples/` in a checkout.

`copilot/copilot_hut.py` is the recipe for Copilot CLI in a hut: it
seals the host's login, writes the policy and installs a pinned release
([MOATHUT-COPILOT.md](../docs/MOATHUT-COPILOT.md)).

The workload's name in these files is `example`, and the brokered
provider is `api.example.com` under the credential id `example`.
Everything else follows from those three.

| file | goes to | |
|---|---|---|
| `systemd/moat-broker.service` | `~/.config/systemd/user/` | the broker, holding the credential |
| `systemd/moat-inspect.socket` | `~/.config/systemd/user/` | the inspector's listeners, 127.0.0.1:8443 and :8080 |
| `systemd/moat-inspect.service` | `~/.config/systemd/user/` | the inspector, started by the socket |
| `systemd/moat-resolve.socket` | `~/.config/systemd/user/` | the responder's port, 127.0.0.1:8053, UDP and TCP |
| `systemd/moat-resolve.service` | `~/.config/systemd/user/` | the workload's nameserver, started by the socket |
| `systemd/moatery-logrotate.{service,timer}` | `~/.config/systemd/user/` | rotation of the record: daily, or hourly once past 100M |
| `logrotate/moatery.conf` | `~/.config/moatery/logrotate.conf` | with `USER` replaced |

The paths below use the default XDG directories: `~/.config` is `%E`
in the units, `~/.local/state` is `%S`, and `~/.local/state/log` is `%L`.

## Once

The policy (see [POLICY.md](../docs/POLICY.md)). The brokered entry names
the endpoints the workload calls: without `paths`, any endpoint that
echoes a request's headers hands the workload the key.

```
mkdir -p ~/.config/moatery
cat > ~/.config/moatery/policy.json <<'EOF'
{"hosts": ["pypi.org", "files.pythonhosted.org"],
 "policy": [{"host": "api.example.com", "methods": ["POST"],
             "paths": ["/v1/messages"], "credential": "example"}]}
EOF
```

An edit applies with `systemctl --user reload moat-inspect
moat-resolve`, which cuts no connection; a change of `tls` needs a
restart.

The credential, sealed to this user on this host. `LoadCredentialEncrypted=`
in a user unit needs systemd 256 or later.

```
systemd-creds --user encrypt --name=example - ~/.config/moatery/example.cred
chmod 0600 ~/.config/moatery/example.cred
```

The egress CA, into the inspector's state directory. Run again, it keeps
the CA that is there; either way it prints the certificate's path.

```
/usr/libexec/moatery/moat-mint-ca --name example \
    --state-dir ~/.local/state/moatery
```

The bundle the workload trusts: the CA over the system store. The
workload's CA variables replace its trust store, so the bundle has to
carry the system CAs too.

```
cat ~/.local/state/moatery/ca/egress-ca.crt \
    /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
    > ~/.config/moatery/bundle.pem
```

(`/etc/ssl/certs/ca-certificates.crt` on Debian-family hosts.)

The units:

```
mkdir -p ~/.config/systemd/user
cp systemd/* ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now moat-broker.service moat-inspect.socket \
    moat-resolve.socket
```

The inspector and the responder start at the first connection and the
first query, so until then `systemctl --user status` shows them
inactive and their sockets listening.

## The container

Steps 4 and 5 of "Host" in [DESIGN.md](../docs/DESIGN.md), for a
container named `example` running `sleep infinity`. The bundle goes
over the image's system trust store, so sudo, which drops the
variables, trusts the CA too; that path is Fedora's, and
`/etc/ssl/certs/ca-certificates.crt` on Debian-family images.

```
T=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
podman create --name example \
    --network pasta:--map-host-loopback=169.254.1.3 --hosts-file image \
    -v "$HOME/.config/moatery/bundle.pem:$T:ro,Z" \
    -e SSL_CERT_FILE=$T -e NODE_EXTRA_CA_CERTS=$T -e REQUESTS_CA_BUNDLE=$T \
    -e EXAMPLE_API_KEY=sk-placeholder \
    registry.fedoraproject.org/fedora:44 sleep infinity
podman init example
DEV=$(ip route show default | awk '{print $5; exit}')
podman unshare nsenter -t "$(podman inspect -f '{{.State.Pid}}' example)" \
  -n nft -f - <<NFT
table inet moatery {
  chain out {
    type nat hook output priority -100
    tcp dport 443 dnat ip to 169.254.1.3:8443
    tcp dport 80  dnat ip to 169.254.1.3:8080
    udp dport 53  dnat ip to 169.254.1.3:8053
    tcp dport 53  dnat ip to 169.254.1.3:8053
  }
}
table netdev moatery {
  chain egress {
    type filter hook egress device "$DEV" priority 0; policy drop
    meta protocol arp accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert,
                  nd-router-solicit } accept
    ip daddr 169.254.1.3 tcp dport { 8443, 8080, 8053 } accept
    ip daddr 169.254.1.3 udp dport 8053 accept
    udp dport 443 counter comment "quic"
    counter comment "dropped"
  }
}
NFT
podman start example
```

Then, from the container, an allowed host answers and any other is
refused by the inspector:

```
podman exec example curl -sI https://pypi.org/simple/    # 200
podman exec example curl -sI https://example.com/        # 403
```

The rules last for this start of the container. A stopped container
started again has a new namespace without them, and its traffic is not
inspected: remove it and run these steps again, or use the quadlet
example ([quadlet/](quadlet/)), which loads them at every start.

## What it writes

- `~/.local/state/log/moatery/requests.log`: one JSON line per request
  or refused connection, mode 0600. Past 512 MiB the inspector drops
  lines, and counts them as write failures, until the file is rotated.
- `~/.local/state/moatery/status.json`: counters, rewritten every 30
  seconds, at a reload and at stop, with the digest of the policy the
  running inspector enforces.
- `~/.local/state/moatery/resolve-status.json`: the responder's counters,
  among them `unlisted`, the queries for names no list admits, and the
  first twenty such names, and `https`, the HTTPS and SVCB queries.
- The journal (`journalctl --user -u moat-inspect -u moat-broker
  -u moat-resolve`): a line per connection and per decision, with the
  reason for every refusal and every 502, and a line per query. A
  connection's line carries the protocols its client offered (`alpn=`),
  and a `note` line reports what refuses nothing by itself: a hello
  carrying ECH, a client offering h2 alone, one opening with HTTP/2's
  preface, and an `Upgrade: h2c` withheld. The status file counts notes by kind under
  `notes`, and offered protocols under `alpn_offered`.
  [LOGGING.md](../docs/LOGGING.md) has every line and key.

## Rotation

The timer and its service were copied with the units above.

```
sed "s/USER/$USER/" logrotate/moatery.conf > ~/.config/moatery/logrotate.conf
systemctl --user enable --now moatery-logrotate.timer
```

## A stop while the broker starts

A user manager prepares a unit's credentials in a directory of its own,
`$XDG_RUNTIME_DIR/systemd/temporary-credentials/UNIT`, and moves them
into place. A stop or restart of the broker while its credential is
being decrypted, which can take over a second, leaves the directory
behind, and every start after fails on it (`Failed to set up
credentials: File exists`) until it is removed:

```
d=$XDG_RUNTIME_DIR/systemd/temporary-credentials/moat-broker.service
chmod -R u+rwX "$d" && rm -rf "$d"
systemctl --user reset-failed moat-broker.service
systemctl --user start moat-broker.service
```

The system manager decrypts into a mount that nothing else sees, and
leaves nothing behind.

## Sandboxing

The units carry no sandboxing directives. In a user unit most of them
(`ProtectSystem=`, `PrivateTmp=` and the like) imply `PrivateUsers=`,
and the broker refuses to start in a user namespace that cannot map its
caller's uid.

## A request filter

[request-filter/](request-filter/) runs every request body to
`api.example.com` through a filter before it leaves
([POLICY.md](../docs/POLICY.md), "Request filters"):

- `json-only`, the filter: it refuses a body that is not JSON, with the
  reason `not-json`, and sends the rest unchanged;
- `sandboxed`, the wrapper the document names: it runs the filter
  beside it under `bwrap`, with no home, no network and no session bus;
- `request-filters.json`, the document, with `HOME` replaced.

The two scripts go where the container cannot write, and the wrapper's
`FILTER=` line names the filter if it is anywhere else:

```
mkdir -p ~/.local/libexec/request-filter
cp -p request-filter/sandboxed request-filter/json-only \
    ~/.local/libexec/request-filter/
sed "s|HOME|$HOME|" request-filter/request-filters.json \
    > ~/.config/moatery/request-filters.json
```

Then add `--request-filters %E/moatery/request-filters.json` to the
inspector's `ExecStart=` and restart it. After that a reload reads the
document again with the policy. The inspector's unit carries no
`RestrictNamespaces=` and allows `@mount`, since bwrap needs both
([DESIGN.md](../docs/DESIGN.md), "Request filters: where they run").

### Logging a part of each body

The second pair keeps a log of what went out:

- `excerpt`, the filter: it sends every body unchanged, and appends a
  line of JSON to `excerpts` with the request's id, ordinal, host,
  method, path, content type and length, and the body's first 256
  bytes. Past 16 MiB the file is moved to `excerpts.1`. A line it
  cannot write fails the request, 502, so no body leaves unlogged;
- `logged`, its wrapper: `sandboxed`'s sandbox, with the one directory
  on its `LOG=` line bound writable as the filter's working directory.

- `request-filters-logged.json`, the document naming `logged`, with
  `HOME` replaced.

The log directory is the workload's bytes as a program that parsed them
wrote them: keep it where the container cannot write, and read it as
untrusted. Install the three, and make the directory:

```
mkdir -p ~/.local/libexec/request-filter ~/.local/state/request-filter
cp -p request-filter/excerpt ~/.local/libexec/request-filter/
sed "s|HOME|$HOME|" request-filter/logged \
    > ~/.local/libexec/request-filter/logged
chmod 755 ~/.local/libexec/request-filter/logged
sed "s|HOME|$HOME|" request-filter/request-filters-logged.json \
    > ~/.config/moatery/request-filters-logged.json
```

For the host units, name that document in the inspector's
`--request-filters`, as above. For a hut, the scripts and the directory
must be outside every hut's home and every mount a hut can write
([MOATHUT.md](../docs/MOATHUT.md), "Request filters"); moathut checks
`run`, not the filter or the directory. A new hut takes the document at
`create`:

```
moathut create NAME --network-policy POLICY \
    --request-filters ~/.config/moatery/request-filters-logged.json
```

and a hut that exists takes it through `request-filters`, with an
editor that copies it in:

```
VISUAL= EDITOR="cp $HOME/.config/moatery/request-filters-logged.json" \
    moathut request-filters NAME
```

Every filtered request then adds a line to
`~/.local/state/request-filter/excerpts`. Its `id` and `req` are the
request's `id` and `req` in the inspector's record (a hut's is
`~/.local/state/log/moatery/hut/NAME/requests.log`) and its `id=` in the
journal:

```
tail -n 5 ~/.local/state/request-filter/excerpts
```

What is logged is the `record` the filter builds: to keep other parts
of the body, change how it sets `head`, and keep each field bounded.

## Elsewhere here

- [quadlet/](quadlet/): a quadlet pod, the listeners in the pod's
  namespace.
- [bootc/](bootc/): a bootc image with moatery and what it recommends.
