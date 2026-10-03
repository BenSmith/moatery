# Placing customs

customs needs one thing from the host: something outside the workload
that owns the workload's outbound sockets, so rules can select them
without the workload's cooperation. This is how to get that with nothing
but a normal user, for each shape that matters. The policy document is
described in [POLICY.md](POLICY.md); ready-made user units for shape 1
are in [examples/](../examples/).

## The same in every shape

- The programs. Flags only, stdlib. The inspector and the responder
  (`customs-resolve`, the workload's nameserver) are socket-activated
  (`LISTEN_FDS`), so where they listen is the `.socket` unit's business,
  not the program's (in shape 1n, `customs-netns-listen` takes the unit's
  place).
- The policy document the inspector reads (`--policy`):

  ```json
  {
    "tls": "inspect",
    "hosts": ["api.example.com"],
    "internal_expected": [],
    "splice": [],
    "policy": [
      {"host": "api.example.com", "methods": ["POST"],
       "paths": ["/v1/messages"], "credential": "example"}
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

## The selector

With root, a workload can be given a uid of its own and its sockets
selected with `meta skuid <uid>` on the host. Without root, every socket
— pasta's, the inspector's, the broker's, the user's IDE — is the same
uid, and it selects nothing.

The replacement is the network namespace. A rootless container's netns is
owned by the user's userns; `podman unshare` is root there, so `nft` loads
into it; the container's processes have no `CAP_NET_ADMIN` in their
bounding set, so they cannot touch what was loaded. The rules see only
the container's traffic, so no exemption is needed to separate the
inspector's own re-originated traffic from the workload's — the
inspector is a namespace out.

Reachability follows from pasta's loopback mapping, which podman turns
off (`--no-map-gw`) and so has to be asked for:

- `--network pasta:--map-host-loopback=169.254.1.3` maps one address in
  the container to host `127.0.0.1`, and only that. A dedicated address
  rather than the gateway, so the gateway stays what it is. The inspector
  binds `127.0.0.1:8443` and `:8080`; the netns rule DNATs 443 and 80 to
  the mapped address.
- The broker listens on a socket path in the user's runtime directory
  (`--listen unix:%t/customs/broker.sock`), which is `0700`. The
  container's mount namespace has no such path, and no other uid on the
  host can traverse to it, so the only caller that can reach the broker
  is the user. A loopback address other than `127.0.0.1` would also be
  out of the container's reach, since pasta maps only the one, but every
  uid on the host could dial it.
- The inspector's listeners are on the host's `127.0.0.1`, which every
  uid on the host can reach. The inspector refuses a caller that is not
  the user, by the kernel's socket table, and while that lookup runs it
  holds one of a few slots; past them it stops accepting rather than
  refusing, so another uid can delay the workload's connections but not
  get them refused. Without root nothing keeps other uids off that port.
  The responder's port is there too, unchecked: another uid can ask it
  names, and learns the one address it gives everyone, and its questions
  are counted with the workload's.
- The inspector recognises exactly 8080 and 8443 as its planes
  (`customs/egress_plane.py`), so this is one inspected container per host
  loopback. A second needs the planes to become a flag, or a second
  loopback address the socket unit binds and pasta maps.
- The workload's port 53, UDP and TCP, whatever the address, is DNATed
  to the responder on the host's `127.0.0.1:8053`, through the same map.
  It answers every name with `169.254.1.3`, so the connection that
  follows is one the 443 and 80 redirect catches; "DNS" below has why
  that is enough. The container is created with `--hosts-file image`:
  podman otherwise seeds its hosts file from the host's, and a name there
  is answered by the file, with the host's address for it, and never
  asked.

`--network host` and `--network none` are out of scope: the first
leaves no namespace to hold the rules, the second no egress to inspect.

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

- **Shape 1b (sidecar):** the pod's netns holds the programs' sockets, and
  the recipe below already marks their connections (`ct mark 0x1`, copied
  onto every packet as `meta mark 0x1`) so the egress chain can exempt
  them. The rule goes in that egress chain after the resolver's lines and
  before its blanket `meta mark 0x1 accept`, which otherwise lets the
  programs out to anywhere. The resolver comes first because it is
  link-local and the programs resolve through it too. The rule keys on
  the mark and the destination -- both readable at the egress hook --
  not on `meta skuid`, which matches only a packet that still carries
  the program's socket:

  ```
  # one line per address an `internal_expected` name resolves to, e.g.
  # meta mark 0x1 ip daddr 10.0.0.5 tcp dport 443 accept
  meta mark 0x1 ip daddr { 0.0.0.0/8, 10.0.0.0/8,
      100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
      192.168.0.0/16 } drop
  meta mark 0x1 ip6 daddr { ::1, fc00::/7, fe80::/10 } drop
  ```

  No `ct state established,related` line: it does not load in a netdev
  egress hook, and it is not needed, because this hook is on the pod's
  egress device and the inspector's replies to the workload go out over
  loopback, which never crosses it. For the same reason the loopback
  entries never reach this chain. The link-local ones do: pasta's
  resolver is there, and so is the host's loopback if the pod maps it
  (`--map-host-loopback`).

  `tests/manual/shape1b_rig.py` runs these lines, with an accept line
  for its stand-in provider on the host's mapped loopback: without that
  line the provider's dial is dropped and never arrives, and the
  programs' own DNS query is answered.
- **Shapes 1, 1n, 2 and 3 with the programs on the host:** there is no rule
  to write without root. The programs' sockets are the user's, like
  everything else the user runs, and the host has no namespace of theirs
  to hold a rule. Here the allowlist is the whole control: keep wildcards
  off domains other people can add names under.

The policy document's `internal_expected` list does not open anything. It
names the hosts the operator has deliberately given a private address (and
an accept line above), so that when a dial into private space fails the
inspector can report `internal destination` -- a name with no accept
line, one edit from working -- rather than `upstream unreachable`. With no
rule loaded that dial succeeds, and the list only changes the report.

## DNS: answered, never forwarded

A resolver that asks another on the workload's behalf is a channel: the
workload puts data in query names and reads data back in answers.
Dropping port 53 does not close it without breaking the workload, whose
clients need a name to resolve before they dial it at all.

So the workload's nameserver is `customs-resolve`, which asks no one. It
answers every A query, for any name, with one address, and every AAAA
with a v6 address if it is given one (`--address6`) and no records if
not; every other type gets NOERROR and no records. The address is one
the workload's 443 and 80 are redirected from, and every recipe below
redirects port 53, UDP and TCP, whatever the address, to the responder,
so a workload that names its own nameserver reaches it too. That is
enough for the redirect, and it is correct, because the inspector dials
the name it authorised and never the address the workload was given.
The responder has no upstream socket: no connect, no resolver call,
which `tests/test_resolve.py` checks by parsing every file it is made
of. A query has nowhere to go. The empty answer to HTTPS/SVCB queries
also withholds the ECH configurations that would hide a name from the
inspector.

A general-purpose resolver configured to do the same would work, but its
default is to forward, and the property would rest on configuration
staying absent. Here it rests on the source.

What remains:

- Everything the workload dials resolves to the inspector's address, so
  a port other than 443 and 80 meets the egress drop, by name as by
  address. Nothing but those two ports leaves in any shape here.
- A name in `--static` is the exception, for a caller whose own filter
  lets a destination past the inspector: it is answered with the
  addresses the map gives, and none for a family the map lacks, since
  the synthesised address does not serve that destination's port. Such
  a name counts as listed.
- The programs' own lookups are not the responder's. In shapes 1 and 1n
  they are the host's; in 1b they go to pasta's forwarder, and the
  egress chain accepts port 53 for the programs' mark alone.
- The responder counts, in its status file, the queries for names no
  list in the inspector's policy admits (`unlisted`, and the first
  twenty such names). Every one is answered like any other, so the
  count is evidence that something is encoding data into names, never
  that anything left.
- A name in the workload's hosts file is never asked: hence
  `--hosts-file image`, which keeps the host's entries out.

## Shape 1: a rootless podman container

```
# 1. CA + bundle + policy.json (examples/README.md)
# 2. broker, user unit; started once it is listening
Type=notify
ExecStart=customs-broker --name x --listen unix:%t/customs/broker.sock \
    --caller-uid %U \
    --host api.example.com=example --placeholder example=sk-placeholder \
    --auth-header example=Authorization \
    "--auth-format=example=Bearer {secret}"
LoadCredentialEncrypted=example:%E/customs/example.cred
RuntimeDirectory=customs
RuntimeDirectoryMode=0700
# 3. inspector, user .socket + .service
ListenStream=127.0.0.1:8443
ListenStream=127.0.0.1:8080
ExecStart=customs-inspect --name x --policy … --state-dir … --status … \
    --record … --broker unix:%t/customs/broker.sock
#    and the responder, user .socket + .service
ListenDatagram=127.0.0.1:8053
ListenStream=127.0.0.1:8053
ExecStart=customs-resolve --name x --address 169.254.1.3 --policy … \
    --status …
# 4. the container, created but not started
podman create --network pasta:--map-host-loopback=169.254.1.3 \
  --hosts-file image \
  -v bundle.pem:/usr/local/share/ca-certificates/egress-ca.crt:ro,Z \
  -e SSL_CERT_FILE=/usr/local/share/ca-certificates/egress-ca.crt \
  -e NODE_EXTRA_CA_CERTS=… -e REQUESTS_CA_BUNDLE=… \
  -e EXAMPLE_API_KEY=sk-placeholder  IMAGE
podman init NAME          # netns exists, entrypoint not yet running
# 5. rules into the netns — this replaces meta skuid. Port 53 is
#    redirected whatever the address: pasta's forwarder is the first
#    nameserver in the container's resolv.conf, and the host's own follow
#    it. The drop is a netdev egress hook, not an output filter: an
#    output `policy drop` fails a UDP send with EPERM, a tell no real
#    network gives, where the egress hook drops the packet after send()
#    returns. It hangs on the egress device — pasta names it after the
#    host's default route, so it is derived, not fixed — and loopback
#    never crosses it. The hook sees the link layer as well as IP, so ARP
#    and neighbour discovery are let through: dropped, the netns loses its
#    gateway's address once the neighbour entry ages out, and every dial
#    to the map fails until it is re-learned. They reach only pasta.
DEV=$(ip route show default | awk '{print $5}')
podman unshare nsenter -t "$(podman inspect -f '{{.State.Pid}}' NAME)" -n nft -f - <<NFT
table inet customs {
  chain out {
    type nat hook output priority -100
    tcp dport 443 dnat ip to 169.254.1.3:8443
    tcp dport 80  dnat ip to 169.254.1.3:8080
    udp dport 53  dnat ip to 169.254.1.3:8053
    tcp dport 53  dnat ip to 169.254.1.3:8053
  }
}
table netdev customs {
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
podman start NAME
```

`create → init → rules → start` closes the first-packet window: no
workload process exists until the rules are in. Step 5 is per-start; a
wrapper or a user unit with `ExecStartPre=` makes it persistent.

The chain's counters are its only trace. `dropped` is every packet it
dropped; `quic` counts the ones among them bound for UDP 443, which is
HTTP/3, before they fall to the drop. A client that tries HTTP/3 and
falls back to TCP is served on the fallback, so the counter is where the
attempt shows. Both are read in the netns:

```
podman unshare nsenter -t PID -n nft list chain netdev customs egress
```

A `log` statement would write nothing: the kernel discards netfilter's
log lines from any namespace but the host's unless
`net.netfilter.nf_log_all_netns` is set, which takes the host's root.

Before step 3 the CA has to exist: `customs-mint-ca --name x
--state-dir DIR`, once, with the inspector's own `--state-dir`. It keeps
a CA that is already there, and prints the certificate's path for the
bundle. The inspector refuses to start without it, by name.

An unlisted host is not a closed connection: under `"inspect"` the
inspector completes the handshake under a leaf its own CA minted for the
refused name and answers 403, so the workload's client sees a real
refusal. The reason is in the record, not the body.

`tests/manual/shape1_rig.py` is this recipe as a rig, and the rig is
where each line above was checked.

IPv6: `--map-host-loopback` takes a v6 address as well, and the filter
chain above is `inet`, so a v6 dial with no rule for it is dropped rather
than leaked. Either rule both families or run pasta `-4`.

## Shape 1n: shape 1 with the listeners in the container's netns

Shape 1, with the inspector's two listeners and the responder's port
bound inside the container's network namespace instead of on the host's
loopback. The inspector process still runs on the host as the user and
dials its upstreams from the host's namespace. The broker is shape 1's,
unchanged.

Against shape 1 this buys:

- No other uid on the host can reach the planes. Nothing listens on the
  host at all; the only processes that can dial the listeners are the
  container's own. In shape 1 every uid can connect, and the caller
  check is what refuses them.
- No loopback map. The container gets plain `--network pasta`, so no
  address in it reaches the host's `127.0.0.1`.
- One inspector per container rather than per host loopback: each
  container's `127.0.0.1:8443` is in its own namespace.
- An egress chain that accepts nothing. The redirect lands 443, 80 and
  53 on the namespace's loopback, which never crosses the egress device.

And costs:

- The listeners belong to one start of the container. A restarted
  container has a new namespace, and the inspector has to be restarted
  with it; one left running holds listeners nothing can reach.
- They are visible from inside. The container's `/proc/net/tcp` (and so
  `ss -ltn`) lists `127.0.0.1:8443`, `:8080` and `:8053` as listening,
  with no process in the container owning them. Shape 1b's listeners
  show the same way; shape 1's are not in the container's table.

**The bind.** A rootless container's network namespace belongs to a user
namespace the user owns. Joining a netns needs `CAP_SYS_ADMIN` over it
and in the joiner's own user namespace, which the user holds only inside
the one it owns. `customs-netns-listen --pid PID -- COMMAND` forks a
child that joins both, by a pidfd of the container's process, binds
`127.0.0.1:8443` and `:8080` there, sends the two listeners back over a
socket pair and exits. The launcher itself never joins: it puts the
listeners on fds 3 and 4, sets `LISTEN_PID` and `LISTEN_FDS`, and execs
the command. The inspector still never binds; the bind is a short-lived
process's, as it is the socket unit's in shape 1. With `--resolver` it
binds the responder's `127.0.0.1:8053`, UDP and TCP, instead. No podman
is involved
past `podman inspect` for the pid, and the pidfd makes a pid that exits
and is reused before the join an error rather than another process's
namespace.

**The caller check.** The caller's socket is in the container's table,
not the host's. `--netns-pid PID` points the inspector's lookups at
`/proc/PID/net/tcp` and `tcp6`. The uid there is the host's view of it:
container root is the user, and every other uid inside is one of the
user's subuids. With `--netns-pid` the inspector serves all of them,
every uid PID's user namespace maps, read from its `uid_map` at start
and logged as `callers served:`. The listeners are on the namespace's
loopback, so nothing outside it can reach them, and every caller is the
workload: its user, root under sudo, a service's own uid. `--caller-uid`
narrows that to one uid; a namespace that maps every uid is refused,
since serving it would serve anyone. At start the inspector also checks
that every listener it was handed has a row in the table its lookups
read, and refuses to start otherwise. Started without `--netns-pid`, it
would look every caller up in the host's table, find none, and admit
them all unnamed.

```
# 1–2. as shape 1: CA + bundle + policy.json; the broker's user unit
# 3. the container, created but not started; plain pasta, no map
podman create --network pasta --hosts-file image \
  -v bundle.pem:/usr/local/share/ca-certificates/egress-ca.crt:ro,Z \
  -e SSL_CERT_FILE=/usr/local/share/ca-certificates/egress-ca.crt \
  -e NODE_EXTRA_CA_CERTS=… -e REQUESTS_CA_BUNDLE=… \
  -e EXAMPLE_API_KEY=sk-placeholder  IMAGE
podman init NAME
PID=$(podman inspect -f '{{.State.Pid}}' NAME)
# 4. rules into the netns: shape 1's, landing on the netns's loopback
DEV=$(ip route show default | awk '{print $5}')
podman unshare nsenter -t "$PID" -n nft -f - <<NFT
table inet customs {
  chain out {
    type nat hook output priority -100
    tcp dport 443 dnat ip to 127.0.0.1:8443
    tcp dport 80  dnat ip to 127.0.0.1:8080
    udp dport 53  dnat ip to 127.0.0.1:8053
    tcp dport 53  dnat ip to 127.0.0.1:8053
  }
}
table netdev customs {
  chain egress {
    type filter hook egress device "$DEV" priority 0; policy drop
    udp dport 443 counter comment "quic"
    counter comment "dropped"
  }
}
NFT
# 5. the inspector and the responder, transient user units for this start
systemd-run --user --unit customs-inspect-NAME -p Type=notify \
  customs-netns-listen --pid "$PID" -- \
  customs-inspect --name x --policy … --state-dir … --status … \
    --record … --broker "unix:$XDG_RUNTIME_DIR/customs/broker.sock" \
    --netns-pid "$PID"
systemd-run --user --unit customs-resolve-NAME -p Type=notify \
  customs-netns-listen --pid "$PID" --resolver -- \
  customs-resolve --name x --address 127.0.0.1 --policy … --status …
podman start NAME
# and at the container's stop
systemctl --user stop customs-inspect-NAME customs-resolve-NAME
```

`create → init → rules → listeners → start`: the workload's first packet
meets both the redirect and a listener. `Type=notify` is what makes the
listener step finish when they are bound: customs-netns-listen sends
READY=1 after the bind and before the exec, so `systemd-run` (or a unit
the workload's is ordered after) returns only then. As `Type=simple`
the unit is started when forked, and a first dial can find nothing
listening and be refused. Nothing the workload may send
crosses the egress device, so the chain accepts nothing, not even the
neighbour discovery shape 1 needs for the map. IPv6 is as in shape 1:
the listeners and the redirect are v4, and a v6 dial falls to the
egress drop.

`tests/manual/shape1n_rig.py` is this recipe as a rig, and
[examples/quadlet/](../examples/quadlet/) as a quadlet pod, which holds
the namespace across restarts of the workload.

## Shape 1b: a sidecar in a pod

Same container, but the inspector is a second container in a `podman
pod` rather than a host process. `podman pod create` starts the infra
container, so the netns exists before any workload process does — rules
go in, then the sidecar starts, then the workload. The redirect is plain
`tcp dport 443 redirect to :8443` on loopback; no gateway mapping.

Two things the host-side placement got for free have to be handled again:

1. **A discriminator.** The inspector's re-originated traffic now leaves
   through the same netns as the workload's, so the rules must tell them
   apart or the inspector redirects itself. Cheapest here: run the sidecar as a different in-pod uid
   and key on `meta skuid` — which requires the workload container to
   hold no `CAP_SETUID`, or workload root simply becomes that uid. Only
   one uid can be the selector. `socket cgroupv2` also works and cannot
   be forged from inside; it is fiddlier.
2. **Broker reachability.** On the host the broker's socket is a path
   the inspector has and the workload's mount namespace does not. In a
   pod the inspector is a container too, and needs a way to the broker
   that the workload lacks. Three placements give one: the broker as a
   third container in the pod behind a `skuid`-keyed rule; the broker on
   the host, its socket bind-mounted into the sidecar alone; or the
   broker inside the same sidecar container as the inspector, which is
   the one taken and is described next. The two AF_UNIX placements keep
   `SO_PEERCRED` as the caller check, which is stronger than
   `/proc/net/tcp`, and the workload has no path to a socket it was never
   given.

There is a third thing, which the host placement also got for free: the
inspector serves connections from its own uid, and here the workload is
another uid *by design*. The inspector's `--caller-uid`, mirroring the
broker's, names it; without the flag every connection is dropped as
foreign.

**The programs in one sidecar container.** The pod shares the network
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
and the socket `0660` under the shared group 200, the inspector as uid 200. 
The inspector is the exposed surface (it parses workload-controlled
ClientHellos and HTTP/1 framing); the broker holds the key; the
socket hop is the line. The responder parses workload-controlled queries
too and holds nothing, so it runs as the inspector's uid. `setuid()` clears every capability, so no
`DAC_OVERRIDE` bridges them whatever the container was started with.

The image is `container/Containerfile`, built from the checkout root, and
its entrypoint `container/customs-sidecar` is the unit file as a process.
As the container's root it binds the two planes and the responder's
port on the pod's loopback, starts the broker as 201 on
`unix:/run/customs/broker.sock` with `CREDENTIALS_DIRECTORY=/run/secrets`,
mints the egress CA into the state volume on the first start, then
starts the inspector as 200 with the planes as fds 3 and 4 and
`LISTEN_PID`/`LISTEN_FDS` set, and the responder as 200 with its own,
answering every name with `127.0.0.1`. No
`systemd-socket-activate`, no systemd in the image: the bind is still not
the inspector's, and it is root's before any privilege is dropped, which
is the socket unit's property by a different route. The entrypoint takes
the two facts the image cannot know -- the workload's label and its uid
-- and passes every other flag to the broker untouched:

```
podman pod create --name POD --hosts-file image --share-parent=false
podman run -d --pod POD --name sidecar --restart on-failure \
    --cap-drop all --cap-add chown,dac_override,setgid,setuid \
    -v policy.json:/etc/customs/policy.json:ro,Z \
    -v customs-state:/var/lib/customs \
    --secret KEY,target=CRED,uid=201,gid=200,mode=0400 \
    customs-sidecar --name NAME --caller-uid 1000 \
    --host api.example.com=CRED --placeholder CRED=sk-placeholder
DEV=$(ip route show default | awk '{print $5}')
podman unshare nsenter -t $(podman inspect -f '{{.State.Pid}}' sidecar) -n \
    nft -f - <<RULES
table inet customs {
  chain out {
    type nat hook output priority -100
    meta skuid { 200, 201 } accept
    tcp dport 443 dnat ip to 127.0.0.1:8443
    tcp dport 80  dnat ip to 127.0.0.1:8080
    udp dport 53  dnat ip to 127.0.0.1:8053
    tcp dport 53  dnat ip to 127.0.0.1:8053
  }
  chain tag {
    type filter hook output priority mangle
    meta skuid { 200, 201 } ct mark set 0x1
    meta mark set ct mark
  }
}
table netdev customs {
  chain egress {
    type filter hook egress device "$DEV" priority 0; policy drop
    meta protocol arp accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert,
                  nd-router-solicit } accept
    meta mark 0x1 ip daddr 169.254.1.1 udp dport 53 accept
    meta mark 0x1 ip daddr 169.254.1.1 tcp dport 53 accept
    meta mark 0x1 accept
    udp dport 443 counter comment "quic"
    counter comment "dropped"
  }
}
RULES
podman run -d --pod POD --name workload --user 1000:1000 --cap-drop all \
    -v bundle.pem:/usr/local/share/ca-certificates/egress-ca.crt:ro,Z \
    -e SSL_CERT_FILE=/usr/local/share/ca-certificates/egress-ca.crt … \
    IMAGE
```

The pod has no cgroup of its own (`--share-parent=false`). With one,
every container's start asks systemd to create the pod's slice unless
podman finds its directory at the path it assumes for the user's
manager, and a slice systemd already has fails that start. Nothing here
sets a limit on the pod as a whole, so the slice would hold nothing the
pod needs.

The programs' upstream dials leave by the same device as the workload's
disallowed egress, so the egress chain has to tell them apart. It cannot
read the uid: `meta skuid` needs the packet to carry the program's
socket, and the segments a connection sends after that socket is gone --
the FIN and RST of a program that exited, TIME_WAIT's ACKs -- carry none.
The `tag` chain reads the uid at the output hook instead, stores it as a
mark on the connection, and copies that onto every packet of the
connection, which the egress hook can read. The mark needs no capability
in the programs: `SO_MARK` would need `CAP_NET_ADMIN`, which the sidecar
does not hold. A source address would need none either, but the workload
shares the netns and could bind the same one.

The four capabilities are the entrypoint's: the chown of the two
directories it hands over, the connect that sees the broker listening, and
the drops. The first-start mint runs as the inspector's uid, not as root:
the volume is the inspector's and outlives restarts, so root writing into
it would follow whatever the inspector left there. The entrypoint refuses
a `--caller-uid` of 0, 200 or 201, the uids the rules exempt, and starts
every program with a minimal environment rather than the container's.
Pasta's forwarder is the programs' resolver, not the workload's:
everyone else's port 53 is redirected to the responder, so its accept
lines carry the programs' mark.

The entrypoint stays as the container's pid 1 and supervises the three,
which serve together or not at all. A stop is forwarded to each program
and the container exits 0. If any exits unasked, the others are stopped
and the container exits 1, so a broker that dies takes the container
with it and the restart policy (or the quadlet's `Restart=`) brings them
back. A restart reuses the volume's CA, so the workload's bundle still
holds. Until they are back, the workload's redirected connections are
refused: nothing listens on the planes and the rules stay in the pod's
netns. The supervisor holds no capability once all have started: its
real uid is 200 and its effective and saved uid 201, which lets it
signal each and is not root.
That is also why it must be pid 1 and refuses `--init`. An init runs as
root without `CAP_KILL`, so it cannot signal a process with no uid 0, and
a stop would reach nobody.
The rules go in after the sidecar starts (the pod's netns exists from
then) and before the workload does. Both image uids are exempt from the
redirect and the drop, since their dials are the upstream legs and leave
through the same netns; the workload holds no `CAP_SETUID`, so it cannot
become one of them. As written the exemption is total, private
addresses included; "Private addresses" above has the lines that narrow
it. The bundle the workload trusts is built from the CA the sidecar
minted (`podman exec sidecar cat
/var/lib/customs/ca/egress-ca.crt`) over the system store. The record's
`upstream` for a brokered request reads `unix:/run/customs/broker.sock`.

The pod's `/proc/self/uid_map` is a rootless one, with the inside and
outside columns different. Both programs' start-up checks read the
inside column, which is the uid the told `--caller-uid` is in.

What the sidecar buys is distribution: the programs become an image, not a
host install. On a host that already carries the RPM, shape 1 is
strictly simpler. In either sidecar variant the CA private key lives
in the pod; a workload-container escape is a host escape, so this is not
a new exposure, but it is worth saying.

Proved by `tests/manual/shape1b_rig.py`, red without the rules. The
probe that is new here: from the workload, the broker's socket path is
ENOENT -- not ECONNREFUSED, which would mean the path exists and the
mount is shared -- and nothing but the two planes and the responder's
port listens on TCP in the pod.

## Shape 2: a VM

Run qemu inside a shape-1 container with `--device /dev/kvm` and
`-netdev passt` (or `passt --socket` + `-netdev stream`). The guest's
egress is now the container's egress and the recipe applies verbatim.
`tests/manual/shape2_rig.py` is this recipe as a rig.
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
  inspector bound on the bridge address. Works and needs root, but
  forwarded packets have no owning uid, so isolation is a per-tap rule set to maintain
  rather than a property to inherit. Only for a VM that must have a LAN
  identity.

This looks backwards — a VM in a container to filter it — but it is the
same move as every other shape: turn forwarded packets into originated
sockets so something outside the guest owns them. With root the owner
can be a uid; without root it has to be a namespace, and the container
is just the cheapest one to get. It contributes no isolation of its own, only the
boundary the rules hang on.

## What customs does not do, on purpose

The programs allocate no uid, write no units, load no rules, install
nothing in the workload, and keep no guest's clock. They mint the CA
only when told to (`customs-mint-ca`, or the sidecar's first start).
Those are host management: they depend on how a host is laid out, and
whoever lays it out does them. `tests/test_closure.py` holds the
programs to importing nothing that knows what a workload is.

`customs-box` is one such layout, shipped in the same RPM: it writes a
box's units and loads its rules ([BOX.md](BOX.md)). It stands beside the
programs; they never import it.

## Proving it

A new placement is proved on a real host, not by unit tests: one
container (or one VM in one) on a KVM host, hand-written
user units, the netns rules, a placeholder in the workload's environment,
and one real request that reaches the provider carrying the sealed key.
Plus the negative probes: dial the broker's address from inside (must
refuse to connect); dial an unlisted host (must be refused by the
inspector); the origin with no key (401). Expect a defect of the "unit
green, packet never arrives" kind.
