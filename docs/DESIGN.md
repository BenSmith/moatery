# Applying customs outside workloadctl

workloadctl runs the pair as root on a hypervisor with a dedicated uid per
workload. This is what it looks like with nothing but a normal user, for
each shape that matters.

## What carries over unchanged

- Both programs. Flags only, no TOML, stdlib. The inspector is
  socket-activated (`LISTEN_FDS`), so where it listens is the `.socket`
  unit's business, not the program's.
- The policy document the inspector reads (`--policy`):

  ```json
  {
    "tls": "inspect",
    "hosts": ["api.example.com"],
    "internal": [],
    "splice": [],
    "http2": [],
    "policy": [
      {"host": "api.example.com", "methods": null, "paths": null,
       "credential": "example"}
    ]
  }
  ```

- Trust injection: the inspector's CA, concatenated with the system CAs,
  mounted into the workload and pointed at by `SSL_CERT_FILE`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`, `PIP_CERT`.
  These variables *replace* the trust store, so the bundle must carry the
  system CAs too, and it must exist before the workload is created.
- The broker's key material via `$CREDENTIALS_DIRECTORY`.
  `LoadCredentialEncrypted=` works in user units on systemd ≥ 256;
  `systemd-creds --user encrypt` seals it.
- The broker's `--caller-uid` check. Under a single user it degenerates to
  "is me", which is fine: the sandbox line is the namespace, and the user
  is on the trusted side of it.

## What changes: the selector

workloadctl selects a workload's sockets with `meta skuid <uid>` on the
host. Without root, every socket — pasta's, the inspector's, the
broker's, the user's IDE — is the same uid, and it selects nothing.

The replacement is the network namespace. A rootless container's netns is
owned by the user's userns; `podman unshare` is root there, so `nft` loads
into it; the container's processes have no `CAP_NET_ADMIN` in their
bounding set, so they cannot touch what was loaded. The rules see only
the container's traffic, so the cgroup exemption workloadctl needs to
separate the inspector's own re-originated traffic from the workload's
disappears — the inspector is a namespace out.

Reachability follows from pasta's loopback mapping, which podman turns
off (`--no-map-gw`) and so has to be asked for:

- `--network pasta:--map-host-loopback=169.254.1.3` maps one address in
  the container to host `127.0.0.1`, and only that. A dedicated address
  rather than the gateway, so the gateway stays what it is. The inspector
  binds `127.0.0.1:8443` and `:8080`; the netns rule DNATs 443 and 80 to
  the mapped address.
- The broker binds any `127.x.y.z ≠ 127.0.0.1`. pasta does not map it,
  so the container cannot dial it at all. That is the whole
  "cannot name the broker" property, done by pasta's mapping rather than
  by a rule.
- The inspector recognises exactly 8080 and 8443 as its planes
  (`lib/egress_plane.py`), so this is one inspected container per host
  loopback. A second needs the planes to become a flag, or a second
  loopback address the socket unit binds and pasta maps.
- DNS goes to pasta's forwarder (`169.254.1.1`, its `--dns-forward`),
  which asks the host's resolver. No synthesising responder is needed:
  the redirect keys on the port and the match is on SNI.

`--network host` and `--network none` are out of scope, exactly as
workloadctl excludes host mode.

## Private addresses: the host's job, not customs'

customs decides by NAME. It does not look at the address an allowed name
resolves to, and neither program refuses a loopback, private or
link-local destination. If an allowed name resolves to one -- a wildcard
over a domain where anyone can register a subdomain, a DNS answer that
changes between the check and the dial, or plain misconfiguration -- the
inspector dials it on 443 or 80, and so does the broker for a brokered
host. In shape 1 the programs run on the host as the user, so a name
that resolves to `127.0.0.1` reaches whatever the user has listening on
the host's loopback.

Stopping that is a rule on the programs' own outbound sockets, and
customs loads no rules. Whoever runs it writes one, where the shape gives
them somewhere to put it:

- **Shape 1b (sidecar):** the pod's netns holds the programs' sockets as
  uids 200 and 201, so the rule goes in the filter chain of the recipe
  below, before `meta skuid { 200, 201 } accept`. These lines load; the
  shape-1b rig does not yet exercise them (its stand-in provider is on a
  TEST-NET address, which this rule would drop):

  ```
  ct state established,related accept
  ip daddr 169.254.1.1 udp dport 53 accept
  ip daddr 169.254.1.1 tcp dport 53 accept
  # one line per address an `internal` name resolves to, e.g.
  # meta skuid { 200, 201 } ip daddr 10.0.0.5 tcp dport 443 accept
  meta skuid { 200, 201 } ip daddr { 0.0.0.0/8, 10.0.0.0/8,
      100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
      192.168.0.0/16 } drop
  meta skuid { 200, 201 } ip6 daddr { ::1, fc00::/7, fe80::/10 } drop
  ```

  `established,related` comes first because the inspector's replies to
  the workload go out over loopback as uid 200.
- **Shapes 1, 2 and 3 with the programs on the host:** there is no rule
  to write without root. The programs' sockets are the user's, like
  everything else the user runs, and the host has no namespace of theirs
  to hold a rule. Here the allowlist is the whole control: keep wildcards
  off domains other people can add names under.

The policy document's `internal` list does not open anything. It names
the hosts the operator has deliberately given a private address (and an
accept line above), so that when a dial into private space fails the
inspector can report `internal destination` -- a name with no accept
line, one edit from working -- rather than `upstream unreachable`. With no
rule loaded that dial succeeds, and the list only changes the report.

## Shape 1: a rootless podman container

```
# 1. CA + bundle + inspect.json (above)
# 2. broker, user unit
ExecStart=customs-broker --name x --listen 127.129.0.1:8081 --caller-uid %U \
    --host api.example.com=example --placeholder example=sk-placeholder \
    --auth-header example=Authorization --auth-format example=Bearer
LoadCredentialEncrypted=example:%h/.config/customs/example.cred
# 3. inspector, user .socket + .service
ListenStream=127.0.0.1:8443
ListenStream=127.0.0.1:8080
ExecStart=customs-inspect --name x --policy … --state-dir … --status … \
    --record … --broker 127.129.0.1:8081
# 4. the container, created but not started
podman create --network pasta:--map-host-loopback=169.254.1.3 \
  -v bundle.pem:/usr/local/share/ca-certificates/customs.crt:ro,Z \
  -e SSL_CERT_FILE=/usr/local/share/ca-certificates/customs.crt \
  -e NODE_EXTRA_CA_CERTS=… -e REQUESTS_CA_BUNDLE=… \
  -e EXAMPLE_API_KEY=sk-placeholder  IMAGE
podman init NAME          # netns exists, entrypoint not yet running
# 5. rules into the netns — this replaces meta skuid. The DNS address is
#    the first nameserver in the container's resolv.conf (podman inspect
#    -f '{{.ResolvConfPath}}'), which is pasta's forwarder.
podman unshare nsenter -t "$(podman inspect -f '{{.State.Pid}}' NAME)" -n nft -f - <<'NFT'
table inet customs {
  chain out {
    type nat hook output priority -100
    tcp dport 443 dnat ip to 169.254.1.3:8443
    tcp dport 80  dnat ip to 169.254.1.3:8080
  }
  chain filter {
    type filter hook output priority 0; policy drop
    oif lo accept
    ip daddr 169.254.1.3 tcp dport { 8443, 8080 } accept
    ip daddr 169.254.1.1 udp dport 53 accept
    ip daddr 169.254.1.1 tcp dport 53 accept
  }
}
NFT
podman start NAME
```

`create → init → rules → start` closes the first-packet window the same
way workloadctl's `ExecStartPre` filter does. Step 5 is per-start; a
wrapper or a user unit with `ExecStartPre=` makes it persistent.

Before step 3 the CA has to exist: nothing here mints it (under
workloadctl `workload-vm-inspect up` does), so the operator runs
`egress_ca.ca_openssl_argv` once into the state directory. The inspector
refuses to start without it, by name.

An unlisted host is not a closed connection: under `"inspect"` the
inspector completes the handshake under a leaf its own CA minted for the
refused name and answers 403, so the workload's client sees a real
refusal. The reason is in the record, not the body.

`tests/manual/shape1_rig.py` is this recipe as a rig, and the rig is
where each line above was checked.

IPv6: `--map-host-loopback` takes a v6 address as well, and the filter
chain above is `inet`, so a v6 dial with no rule for it is dropped rather
than leaked. Either rule both families or run pasta `-4`.

## Shape 1b: a sidecar in a pod

Same container, but the inspector is a second container in a `podman
pod` rather than a host process. `podman pod create` starts the infra
container, so the netns exists before any workload process does — rules
go in, then the sidecar starts, then the workload. The redirect is plain
`tcp dport 443 redirect to :8443` on loopback; no gateway mapping.

Two things the host-side placement got for free have to be handled again:

1. **A discriminator.** The inspector's re-originated traffic now leaves
   through the same netns as the workload's, so the rules must tell them
   apart or the inspector redirects itself. workloadctl solves this with
   a cgroup. Cheapest here: run the sidecar as a different in-pod uid
   and key on `meta skuid` — which requires the workload container to
   hold no `CAP_SETUID`, or workload root simply becomes that uid. Only
   one uid can be the selector. `socket cgroupv2` also works and cannot
   be forged from inside; it is fiddlier.
2. **Broker reachability.** The host's `127.129.0.1` is unmapped from the
   pod, so "the workload cannot name the broker" is no longer something
   pasta's mapping gives for free. Three placements restore it: the
   broker as a third container in the pod behind a `skuid`-keyed rule;
   the broker on the host, listening on an AF_UNIX socket bind-mounted
   into the sidecar alone; or the broker inside the same sidecar
   container as the inspector, which is the one taken and is described
   next. The two AF_UNIX placements share an advantage: `SO_PEERCRED` is
   a stronger caller check than `/proc/net/tcp`, and the workload has no
   path to a socket it was never given. Both use the broker's
   `--listen unix:PATH` and the inspector's matching `--broker unix:PATH`.

There is a third thing, which the host placement also got for free: the
inspector serves connections from its own uid, and here the workload is
another uid *by design*. The inspector's `--caller-uid`, mirroring the
broker's, names it; without the flag every connection is dropped as
foreign.

**Both programs in one sidecar container.** The pod shares the network
namespace, not the mount namespace, so the broker can listen on a
filesystem AF_UNIX socket in the sidecar's own tmpfs
(`/run/customs/broker.sock`); the inspector beside it dials that, and the
workload container has no path to it — not by rule, by there being no
such file in its mount namespace. (A path socket, not an abstract one:
abstract socket names live in the netns, and the workload could reach
one.) This is the "unmapped address" property back by a different
mechanism, without a second image or a host install.

The privilege boundary between the two programs survives inside one
container as two uids: the broker as uid 201 owning the key file `0400`
and the socket `0660` under the shared group 200, the inspector as uid
200. The inspector is the exposed surface (it parses workload-controlled
ClientHellos and HTTP/1 and /2 framing); the broker holds the key; the
socket hop is the line. `setuid()` clears every capability, so no
`DAC_OVERRIDE` bridges them whatever the container was started with.

The image is `container/Containerfile`, built from the checkout root, and
its entrypoint `container/customs-sidecar` is the unit file as a process.
As the container's root it binds the two planes on the pod's loopback,
starts the broker as 201 on `unix:/run/customs/broker.sock` with
`CREDENTIALS_DIRECTORY=/run/secrets`, mints the egress CA into the state
volume on the first start, then drops to 200 and execs the inspector with
the listeners as fds 3 and 4 and `LISTEN_PID`/`LISTEN_FDS` set. No
`systemd-socket-activate`, no systemd in the image: the bind is still not
the inspector's, and it is root's before any privilege is dropped, which
is the socket unit's property by a different route. The entrypoint takes
the two facts the image cannot know -- the workload's label and its uid
-- and passes every other flag to the broker untouched:

```
podman pod create --name POD
podman run -d --pod POD --name sidecar --init \
    --cap-drop all --cap-add chown,dac_override,setgid,setuid \
    -v policy.json:/etc/customs/policy.json:ro,Z \
    -v customs-state:/var/lib/customs \
    --secret KEY,target=CRED,uid=201,gid=200,mode=0400 \
    customs-sidecar --name NAME --caller-uid 1000 \
    --host api.example.com=CRED --placeholder CRED=sk-placeholder
podman unshare nsenter -t $(podman inspect -f '{{.State.Pid}}' sidecar) -n \
    nft -f - <<'RULES'
table inet customs {
  chain out {
    type nat hook output priority -100
    meta skuid { 200, 201 } accept
    tcp dport 443 dnat ip to 127.0.0.1:8443
    tcp dport 80  dnat ip to 127.0.0.1:8080
  }
  chain filter {
    type filter hook output priority 0; policy drop
    meta skuid { 200, 201 } accept
    oif lo accept
    ip daddr 169.254.1.1 udp dport 53 accept
    ip daddr 169.254.1.1 tcp dport 53 accept
  }
}
RULES
podman run -d --pod POD --name workload --user 1000:1000 --cap-drop all \
    -v bundle.pem:/usr/local/share/ca-certificates/customs.crt:ro,Z \
    -e SSL_CERT_FILE=/usr/local/share/ca-certificates/customs.crt … \
    IMAGE
```

The four capabilities are the entrypoint's: the chown of the two
directories it hands over, the mint into one of them, and the two drops.
The rules go in after the sidecar starts (the pod's netns exists from
then) and before the workload does. Both image uids are exempt from the
redirect and the drop, since their dials are the upstream legs and leave
through the same netns; the workload holds no `CAP_SETUID`, so it cannot
become one of them. As written the exemption is total, private addresses
included; "Private addresses" above has the lines that narrow it. The bundle the workload trusts is built from the CA
the sidecar minted (`podman exec sidecar cat
/var/lib/customs/ca/egress-ca.crt`) over the system store. The record's
`upstream` for a brokered request reads `unix:/run/customs/broker.sock`.

The pod's `/proc/self/uid_map` is a rootless one, with the inside and
outside columns different, and that is what found the pair's one seam
defect here: the namespace check compared the told uid against the
outside column, and refused uid 200. Every earlier layout had the columns
equal. `peer_identity.userns_ranges` now reads the inside column.

What the sidecar buys is distribution: the pair becomes an image, not a
host install. That is the cosy-shaped requirement — cosy is one script
that installs nothing. On a host that already carries the RPM, shape 1
is strictly simpler. In either sidecar variant the CA private key lives
in the pod; a workload-container escape is a host escape, so this is not
a new exposure, but it is worth saying.

Proved 2026-09-22 by `tests/manual/shape1b_rig.py`: 18 rows, red without
the rules. The probe that is new here: from the workload, the broker's
socket path is ENOENT -- not ECONNREFUSED, which would mean the path
exists and the mount is shared -- and nothing but the two planes listens
on TCP in the pod.

## Shape 2: a VM

Run qemu inside a shape-1 container with `--device /dev/kvm` and
`-netdev passt` (or `passt --socket` + `-netdev stream`). The guest's
egress is now the container's egress and the recipe applies verbatim.
Guest root can rewrite the guest's own nft all day; the rules that matter
are one namespace out, where qemu and passt hold no `CAP_NET_ADMIN`.

Guest-side touches, both via the cloud-init seed: the CA bundle plus the
env vars, and the placeholder in the agent's environment.

Friction to expect: SELinux on `/dev/kvm` inside `container_t`
(`container_use_devices` or a label opt-out); virtiofs/9p if a shared
directory is wanted.

The other two VM shapes, for the record:

- **Session libvirt / user-run qemu with passt on the host.** No selector
  exists: passt re-originates as the user, the guest owns its own netns,
  and there is no namespace of the user's to hold rules. Wrapping
  qemu+passt in a hand-made `pasta` netns is shape 2 without the image.
- **System libvirt on a bridge (root).** Selector is the tap or the
  bridge, rules in `prerouting`/`forward` on the host from a libvirt hook,
  inspector bound on the bridge address. Works, needs root, and it is the
  design workloadctl walked away from (its ADR 006): forwarded packets
  have no owning uid, so isolation is a per-tap rule set to maintain
  rather than a property to inherit. Only for a VM that must have a LAN
  identity.

This looks backwards — a VM in a container to filter it — but it is the
move ADR 006 already made: turn forwarded packets into originated sockets
so something outside the guest owns them. On the hypervisor the owner is
a uid; without root it has to be a namespace, and the container is just
the cheapest one to get. It contributes no isolation of its own, only the
boundary the rules hang on.

## Shape 3: a cosy container

[cosy](https://github.com/BenSmith/cosy) is shape 1 — or, since it
installs nothing on the host, shape 1b — with a home directory and a
display. Its `cosy network` subcommand already enters the container's
netns from the host via `podman unshare nsenter`, so the rule step has a
place to live, and cosy passes `--volume`/`--env` through to podman. What
cosy would need to grow: a way to say the policy (`cosy network policy
NAME --allow HOST --credential HOST=CRED` writing the JSON) and either
the user units or the sidecar. Base cosy containers hold 5 capabilities,
none of them `NET_ADMIN`; a cosy container on a custom network gains
`NET_ADMIN` and is out of scope.

## What workloadctl has that this does not, on purpose

No dedicated uid, no cgroup discriminator, no generator, no drift/status
run-files, no SELinux domain for the inspector, no clock keeper after a
VM pause, no QMP-driven guest checks, no resolver oracle. None of those
were the pair's; they were host management, which is why the closure
tests could fence them out.

## Proving it

The same discipline that found every real defect the pair had under
workloadctl: one container (or one VM in one) on a KVM host, hand-written
user units, the netns rules, a placeholder in the workload's environment,
and one real request that reaches the provider carrying the sealed key.
Plus the negative probes: dial the broker's address from inside (must
refuse to connect); dial an unlisted host (must be refused by the
inspector); the origin with no key (401). Expect a seam defect of the
"unit green, packet never arrives" kind; every substrate so far had one.
