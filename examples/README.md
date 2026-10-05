# Examples: the host placement as user units

Units for a rootless podman container inspected by moatery, its
inspector, broker and responder running as the user on the host
([DESIGN.md](../docs/DESIGN.md), "Host"). They assume the RPM is
installed (`just rpm` builds it): the programs in
`/usr/libexec/moatery/`, the `moatery` package where Python finds it,
and these files in `/usr/share/doc/moatery/examples/`. The commands
below are run from that directory, or from `examples/` in a checkout.

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

## Elsewhere here

- [quadlet/](quadlet/): a quadlet pod, the listeners in the pod's
  namespace.
- [bootc/](bootc/): a bootc image with moatery and what it recommends.
