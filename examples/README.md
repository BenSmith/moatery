# Examples: shape 1 as user units

Units for a rootless podman container inspected by the pair running as
the user on the host ([DESIGN.md](../docs/DESIGN.md), shape 1). They
assume the programs are installed at `/usr/libexec/customs/`, with the
modules under `lib/` in the same directory:

```
sudo install -d /usr/libexec/customs
sudo install -m 0644 lib/*.py /usr/libexec/customs/
sudo install -m 0755 libexec/customs-broker libexec/customs-inspect \
    /usr/libexec/customs/
```

The workload's name in these files is `example`, and the brokered
provider is `api.example.com` under the credential id `example`.
Everything else follows from those three.

| file | goes to | |
|---|---|---|
| `systemd/customs-broker.service` | `~/.config/systemd/user/` | the broker, holding the credential |
| `systemd/customs-inspect.socket` | `~/.config/systemd/user/` | the inspector's listeners, 127.0.0.1:8443 and :8080 |
| `systemd/customs-inspect.service` | `~/.config/systemd/user/` | the inspector, started by the socket |
| `systemd/customs-logrotate.{service,timer}` | `~/.config/systemd/user/` | daily rotation of the record |
| `logrotate/customs.conf` | `~/.config/customs/logrotate.conf` | with `USER` replaced |

The paths below use the default XDG directories: `~/.config` is `%E`
in the units, `~/.local/state` is `%S`, and `~/.local/state/log` is `%L`.

## Once

The policy (see [POLICY.md](../docs/POLICY.md)):

```
mkdir -p ~/.config/customs
cat > ~/.config/customs/policy.json <<'EOF'
{"hosts": ["pypi.org", "files.pythonhosted.org"],
 "policy": [{"host": "api.example.com", "credential": "example"}]}
EOF
```

The credential, sealed to this user on this host. `LoadCredentialEncrypted=`
in a user unit needs systemd 256 or later.

```
systemd-creds --user encrypt --name=example - ~/.config/customs/example.cred
chmod 0600 ~/.config/customs/example.cred
```

The egress CA. The programs do not mint it; this runs the inspector's own
`openssl` invocation into its state directory:

```
python3 -c '
import subprocess, sys, time
sys.path.insert(0, "/usr/libexec/customs")
from egress_ca import ca_cert_path, ca_key_path, ca_openssl_argv
state, name = sys.argv[1:]
ca_key_path(state).parent.mkdir(mode=0o700, parents=True)
subprocess.run(ca_openssl_argv(name, ca_key_path(state), ca_cert_path(state),
                               now=time.time()), check=True)
' ~/.local/state/customs example
```

The bundle the workload trusts: the CA over the system store. The
workload's CA variables replace its trust store, so the bundle has to
carry the system CAs too.

```
cat ~/.local/state/customs/ca/egress-ca.crt \
    /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
    > ~/.config/customs/bundle.pem
```

(`/etc/ssl/certs/ca-certificates.crt` on Debian-family hosts.)

Then:

```
systemctl --user daemon-reload
systemctl --user enable --now customs-broker.service customs-inspect.socket
```

The container, and the rules that send its traffic to the inspector,
are steps 4 and 5 of shape 1 in [DESIGN.md](../docs/DESIGN.md).

## What it writes

- `~/.local/state/log/customs/requests.log`: one JSON line per request
  or refused connection, mode 0600.
- `~/.local/state/customs/status.json`: counters, rewritten every 30
  seconds and at stop, with the digest of the policy the running
  inspector loaded.
- The journal (`journalctl --user -u customs-inspect -u customs-broker`):
  a line per connection and per decision, with the reason for every
  refusal and every 502.

## Rotation

```
sed "s/USER/$USER/" logrotate/customs.conf > ~/.config/customs/logrotate.conf
systemctl --user enable --now customs-logrotate.timer
```

## Sandboxing

The units carry no sandboxing directives. In a user unit most of them
(`ProtectSystem=`, `PrivateTmp=` and the like) imply `PrivateUsers=`,
and the broker refuses to start in a user namespace that cannot map its
caller's uid.
