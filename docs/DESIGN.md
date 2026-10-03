# Placing customs

customs inspects what a workload sends out and brokers the credentials
it uses, without the workload's cooperation and without root. This
document is how its programs are placed around a workload: what they
need from the host, what is the same wherever they run, and four
placements, each run end to end on a real host.

[POLICY.md](POLICY.md) is the policy document, [LOGGING.md](LOGGING.md)
what customs reports, and [BOX.md](BOX.md) customs-box, which lays out
the netns placement below for you.

## What customs needs from the host

Something outside the workload has to own the workload's outbound
sockets, so that rules can select them without the workload's
cooperation.

That owner is a network namespace the user is root in and the workload
is not. A rootless podman container is the cheapest one to get: its
network namespace belongs to the user's user namespace, where `podman
unshare` is root, so `nft` loads rules into it; the container's
processes hold no `CAP_NET_ADMIN`, so they cannot touch what was
loaded. The rules see only the container's traffic. A VM is placed
the same way, as one more process inside such a container.

A uid cannot be the selector without root. Every socket the user opens
— pasta's, the inspector's, the broker's, the user's editor's — has
the user's uid, so a rule on the uid selects nothing. With root it can
be ("With root" below).

`--network host` and `--network none` are out of scope: the first
leaves no namespace to hold the rules, the second no egress to inspect.

## The parts

Three programs run beside each workload, the same in every placement:

- **`customs-inspect`**, the egress inspector. The workload's outbound
  443 and 80 are redirected into it. It reads the name the workload
  asked for, matches it against the policy, terminates TLS under a CA
  the workload trusts (or, for a spliced host, passes it through
  unread), re-originates each permitted request itself, and
  sends a request for a brokered host to the broker instead of the
  origin. It is socket-activated: it is handed its two listeners
  (`LISTEN_FDS`), `:8443` for TLS and `:8080` for cleartext
  (`customs/egress_plane.py`), and never binds them, so where they are
  is the placement's choice. It serves only the workload's callers,
  looked up in the kernel's socket table.
- **`customs-broker`**, the credential broker. It holds the real key,
  read from `$CREDENTIALS_DIRECTORY`, and the inspector is its only
  caller: it listens on a filesystem socket (`--listen unix:PATH`) the
  workload has no path to, and serves one uid (`--caller-uid`), checked
  with `SO_PEERCRED`. It discards whatever credential header a request
  carries, attaches the real one, and dials the provider itself.
- **`customs-resolve`**, the workload's nameserver. The workload's port
  53 is redirected to it, on `:8053`, UDP and TCP. It answers and never
  forwards ("DNS" below). It is socket-activated like the inspector.

Two programs set them up:

- **`customs-mint-ca`** makes the workload's CA once, in the inspector's
  `--state-dir`, before the inspector first starts. It keeps a CA that
  is already there and prints the certificate's path either way. The
  inspector refuses to start without one, and says so.
- **`customs-netns-listen`** binds the inspector's or the responder's
  listeners inside a container's network namespace and hands them over
  ("Netns" below).

And three pieces of configuration:

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

- The trust bundle: the workload's CA concatenated with the system CAs,
  mounted into the workload and pointed at by `SSL_CERT_FILE`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` and
  `PIP_CERT`. These variables replace the trust store, so the bundle
  carries the system CAs too, and it must exist before the workload is
  created.
- The credential, sealed to the user on the host with `systemd-creds
  --user encrypt` and handed to the broker by `LoadCredentialEncrypted=`
  in its unit, which a user unit takes from systemd 256. The workload
  holds a placeholder in its place.

Where the programs run on the host as the user, the broker's caller
check comes down to "is me". That is enough: the line customs draws is
the namespace, and the user is on the trusted side of it.

## The rules

The rules go into the workload's network namespace with `podman unshare
nsenter`, after `podman init` has made the namespace and before `podman
start` runs the workload: `create → init → rules → start`, so the first
packet the workload sends meets them. They last for one start of the
container; a unit's `ExecStartPre=`, or a quadlet pod's
`ExecStartPost=`, loads them at every start.

There are two tables. Each placement's recipe below gives them in full,
since what they redirect to and what they accept differ:

- **The redirect**, `table inet customs`, a nat output chain: TCP 443 to
  the inspector's `:8443`, TCP 80 to its `:8080`, and port 53, UDP and
  TCP, to the responder's `:8053`. Port 53 is redirected whatever the
  address, since pasta's forwarder is the first nameserver in the
  container's `resolv.conf` and the host's own nameservers follow it.
- **The drop**, `table netdev customs`, an egress chain on the
  namespace's egress device with `policy drop`. It is a netdev egress
  hook, not an output filter: an output `policy drop` fails a UDP send
  with `EPERM`, a tell no real network gives, where the egress hook
  drops the packet after `send()` has returned. pasta names the device
  after the host's default route, so the recipes derive it (`ip route
  show default`). Loopback never crosses it. The chain sees the link
  layer as well as IP, so a placement that reaches anything through
  pasta lets ARP and neighbour discovery through: dropped, the
  namespace loses its gateway's address once the neighbour entry ages
  out, and every dial through pasta fails until it is learned again.
  Those packets reach only pasta.

The drop chain's counters are its only trace. `dropped` counts every
packet it dropped; `quic` counts those bound for UDP 443, which is
HTTP/3, before they fall to the drop. A client that tries HTTP/3 and
falls back to TCP is served on the fallback, so the counter is where
the attempt shows. Both are read in the namespace:

```
podman unshare nsenter -t PID -n nft list chain netdev customs egress
```

A `log` statement would write nothing: the kernel discards netfilter's
log lines from any namespace but the host's unless
`net.netfilter.nf_log_all_netns` is set, which takes the host's root.

The listeners and the redirect are IPv4. The drop chain drops whatever
it does not accept, in either family, so an IPv6 dial is dropped rather
than leaked.

## DNS: answered, never forwarded

A resolver that asks another on the workload's behalf is a channel: the
workload puts data in query names and reads data back in answers.
Dropping port 53 does not close it without breaking the workload, whose
clients need a name to resolve before they dial it at all.

So the workload's nameserver is `customs-resolve`, which asks no one. It
answers every A query, for any name, with one address (`--address`), and
every AAAA with a v6 address if it is given one (`--address6`) and no
records if not; every other type gets NOERROR and no records. The
address is one the workload's 443 and 80 are redirected from, and every
placement redirects port 53 to the responder whatever the address, so a
workload that names its own nameserver reaches it too. That is enough
for the redirect, and it is correct, because the inspector dials the
name it authorised and never the address the workload was given. The
responder has no upstream socket: no connect, no resolver call, which
`tests/test_resolve.py` checks by parsing every file it is made of. A
query has nowhere to go. The empty answer to HTTPS and SVCB queries
also withholds the ECH configurations that would hide a name from the
inspector.

A general-purpose resolver configured to do the same would work, but its
default is to forward, and the property would rest on configuration
staying absent. Here it rests on the source.

What remains:

- Everything the workload dials resolves to the inspector's address, so
  a port other than 443 and 80 meets the drop, by name as by address.
  Nothing of the workload's but those two ports leaves.
- A name in `--static` is the exception, for a caller whose own filter
  lets a destination past the inspector: it is answered with the
  addresses the map gives, and none for a family the map lacks, since
  the synthesised address does not serve that destination's port. Such
  a name counts as listed.
- The programs' own lookups are not the responder's. Where the programs
  run on the host they are the host's; in the sidecar they go to pasta's
  forwarder, and the drop chain accepts port 53 for the programs alone.
- The responder counts, in its status file, the queries for names no
  list in the inspector's policy admits (`unlisted`, and the first
  twenty such names). Every one is answered like any other, so the
  count is evidence that something is encoding data into names, never
  that anything left.
- A name in the workload's hosts file is never asked. Every placement
  creates the container or pod with `--hosts-file image`; podman
  otherwise seeds the file from the host's, which answers a name with
  the host's address for it.

## Private addresses: the host's job, not customs'

customs decides by name. It does not look at the address an allowed
name resolves to, and neither the inspector nor the broker refuses a
loopback, private or link-local destination. If an allowed name
resolves to one — a wildcard over a domain where anyone can register a
subdomain, a DNS answer that changes between the check and the dial, or
plain misconfiguration — the inspector dials it on 443 or 80, and so
does the broker for a brokered host. Where the programs run on the host
as the user, a name that resolves to `127.0.0.1` reaches whatever the
user has listening on the host's loopback.

Stopping that is a rule on the programs' own outbound sockets, and
customs loads no rules. Whoever places it writes one, where the
placement gives them somewhere to put it:

- **Host, netns and VM**, with the programs on the host: there is no
  rule to write without root. The programs' sockets are the user's, like
  everything else the user runs, and the host has no namespace of
  theirs to hold a rule. Here the policy is the whole control: keep
  wildcards off domains other people can add names under.
- **Sidecar**: the pod's namespace holds the programs' sockets, and the
  recipe already marks their connections (`ct mark 0x1`, copied onto
  every packet as `meta mark 0x1`) so the drop chain can exempt them.
  The rule goes in that chain after the resolver's lines and before its
  blanket `meta mark 0x1 accept`, which otherwise lets the programs out
  to anywhere. The resolver comes first because it is link-local and
  the programs resolve through it too. The rule keys on the mark and the
  destination — both readable at the egress hook — not on `meta
  skuid`, which matches only a packet that still carries the program's
  socket:

  ```
  # one line per address an `internal_expected` name resolves to, e.g.
  # meta mark 0x1 ip daddr 10.0.0.5 tcp dport 443 accept
  meta mark 0x1 ip daddr { 0.0.0.0/8, 10.0.0.0/8,
      100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
      192.168.0.0/16 } drop
  meta mark 0x1 ip6 daddr { ::1, fc00::/7, fe80::/10 } drop
  ```

  No `ct state established,related` line: it does not load in a netdev
  egress hook, and it is not needed, because the inspector's replies to
  the workload go out over loopback, which never crosses the egress
  device. For the same reason the loopback entries never reach this
  chain. The link-local ones do: pasta's resolver is there, and so is
  the host's loopback if the pod maps it (`--map-host-loopback`).
  `tests/manual/sidecar_rig.py` runs these lines, with an accept line
  for its stand-in provider on the host's mapped loopback.

The policy's `internal_expected` list opens nothing. It names the hosts
the operator has deliberately given a private address (and an accept
line above), so that when a dial into private space fails the inspector
can report `internal destination` — a name with no accept line, one
edit from working — rather than `upstream unreachable`. With no rule
loaded that dial succeeds, and the list only changes the report.

## Choosing a placement

| placement | the programs | the listeners | who else can reach them |
|---|---|---|---|
| host | user units on the host | the host's `127.0.0.1`, through a loopback address pasta maps | every uid on the host; the inspector refuses them |
| netns | user units on the host | the container's own loopback | nothing outside the container |
| sidecar | a second container in the workload's pod | the pod's loopback | nothing outside the pod |
| VM | as host, with qemu as the workload | as host | as host |

- **Host** is the plainest: a socket unit binds the listeners, and
  [examples/](../examples/) has its units. The inspector's ports are
  fixed, so it is one inspected container per host loopback.
- **Netns** keeps every other uid off the listeners, and gives every
  container its own. Its listeners belong to one start of the container,
  so they are started with it; [examples/quadlet/](../examples/quadlet/)
  does that with a pod, and customs-box ([BOX.md](BOX.md)) is built on
  it.
- **Sidecar** needs no host install: the programs are an image. It
  needs more rules, since the programs' own dials leave through the
  workload's namespace.
- **VM** is the host placement with qemu as the workload.

## Host: a rootless podman container, listeners on the host

**What runs where.** The three programs run on the host as the user's
units. The container reaches them through one loopback address pasta
maps to the host's `127.0.0.1`, which podman turns off
(`--no-map-gw`) and so has to be asked for:
`--network pasta:--map-host-loopback=169.254.1.3`. A dedicated address
rather than the gateway, so the gateway stays what it is. The rules
redirect 443, 80 and 53 to that address, and the responder answers
every name with it.

- The inspector's socket unit binds `127.0.0.1:8443` and `:8080` on the
  host, which every uid on the host can reach. The inspector refuses a
  caller that is not the user, by the kernel's socket table, and while
  that lookup runs it holds one of a few slots; past them it stops
  accepting rather than refusing, so another uid can delay the
  workload's connections but not get them refused. Nothing keeps other
  uids off the port without root.
- The responder's socket unit binds `127.0.0.1:8053` there too,
  unchecked: another uid can ask it names, learns the one address it
  gives everyone, and its questions are counted with the workload's.
- The broker listens on a path in the user's runtime directory (`--listen
  unix:%t/customs/broker.sock`), which is `0700`. The container's mount
  namespace has no such path and no other uid on the host can traverse
  to it, so the only caller that can reach the broker is the user. A
  loopback address other than `127.0.0.1` would also be out of the
  container's reach, since pasta maps only the one, but every uid on
  the host could dial it.
- The inspector recognises exactly `:8080` and `:8443` as its listeners
  (`customs/egress_plane.py`), so this is one inspected container per
  host loopback. A second needs the ports to become a flag, or a second
  loopback address the socket unit binds and pasta maps.

**The recipe.**

```
# 1. the policy, the credential, the CA and the bundle (examples/README.md)
customs-mint-ca --name x --state-dir DIR    # the inspector's --state-dir
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
ExecStart=customs-inspect --name x --policy … --state-dir DIR --status … \
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
podman init NAME          # the namespace exists, the workload does not
# 5. the rules
DEV=$(ip route show default | awk '{print $5}')
podman unshare nsenter -t "$(podman inspect -f '{{.State.Pid}}' NAME)" \
  -n nft -f - <<NFT
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

The redirect sends the workload's traffic to the mapped address, and
the drop chain accepts only that address's three ports, and the
neighbour discovery that keeps the map reachable. `--map-host-loopback`
takes a v6 address as well; map one only with rules for it in both
tables, or run pasta `-4`.

**What it buys and costs.** Nothing to start per container: the socket
units bind once and the inspector starts at the first dial. Against
that, the listeners are on the host, where every uid can reach them,
and one host loopback serves one container.

**Proved by** `tests/manual/host_rig.py`, which runs this recipe; the
user units are in [examples/systemd/](../examples/systemd/).

## Netns: the listeners in the container's network namespace

**What runs where.** The three programs run on the host as the user,
and the broker is the host placement's unit, unchanged. The inspector's
two listeners and the responder's port are bound inside the container's
network namespace, on its own `127.0.0.1`, so the redirect lands on the
namespace's loopback and the container needs no loopback map. The
inspector still dials its upstreams from the host's namespace.

**The bind.** A rootless container's network namespace belongs to a
user namespace the user owns. Joining a network namespace needs
`CAP_SYS_ADMIN` over it and in the joiner's own user namespace, which
the user holds only inside the one it owns. `customs-netns-listen --pid
PID — COMMAND` forks a child that joins both, by a pidfd of the
container's process, binds `127.0.0.1:8443` and `:8080` there, sends the
two listeners back over a socket pair and exits. The launcher itself
never joins: it puts the listeners on fds 3 and 4, sets `LISTEN_PID`
and `LISTEN_FDS`, and execs the command. The inspector still never
binds; the bind is a short-lived process's, as it is the socket unit's
on the host. With `--resolver` it binds the responder's
`127.0.0.1:8053`, UDP and TCP, instead. Nothing of podman is involved
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

**The recipe.**

```
# 1-2. as on the host: the policy, the credential, the CA, the bundle,
#      and the broker's user unit
# 3. the container, created but not started; plain pasta, no map
podman create --network pasta --hosts-file image \
  -v bundle.pem:/usr/local/share/ca-certificates/egress-ca.crt:ro,Z \
  -e SSL_CERT_FILE=/usr/local/share/ca-certificates/egress-ca.crt \
  -e NODE_EXTRA_CA_CERTS=… -e REQUESTS_CA_BUNDLE=… \
  -e EXAMPLE_API_KEY=sk-placeholder  IMAGE
podman init NAME
PID=$(podman inspect -f '{{.State.Pid}}' NAME)
# 4. the rules, landing on the namespace's loopback
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

`create → init → rules → listeners → start`: the workload's first
packet meets both the redirect and a listener. `Type=notify` is what
makes the listener step finish when they are bound: customs-netns-listen
sends `READY=1` after the bind and before the exec, so `systemd-run`, or
a unit the workload's is ordered after, returns only then. As
`Type=simple` the unit is started when forked, and a first dial can
find nothing listening and be refused. Nothing the workload may send
crosses the egress device, so the drop chain accepts nothing, not even
neighbour discovery.

**What it buys and costs.**

- No other uid on the host can reach the listeners. Nothing listens on
  the host at all; the only processes that can dial them are the
  container's own.
- No loopback map: no address in the container reaches the host's
  `127.0.0.1`.
- One inspector per container: each container's `127.0.0.1:8443` is in
  its own namespace.
- A drop chain that accepts nothing.
- The listeners belong to one start of the container. A restarted
  container has a new namespace, and the inspector has to be restarted
  with it; one left running holds listeners nothing can reach. A
  quadlet pod holds the namespace across restarts of the workload.
- They are visible from inside. The container's `/proc/net/tcp`, and so
  `ss -ltn`, lists `127.0.0.1:8443`, `:8080` and `:8053` as listening,
  with no process in the container owning them. The sidecar's listeners
  show the same way.

**Proved by** `tests/manual/netns_rig.py`, which runs this recipe;
[examples/quadlet/](../examples/quadlet/) is it as a quadlet pod, and
`tests/manual/box_rig.py` proves customs-box, which lays it out per box.

## Sidecar: customs in the workload's pod

**What runs where.** The three programs run in one container, the
sidecar, in a `podman pod` beside the workload's container. The pod
shares its network namespace among its containers, and not its mount
namespace. `podman pod create` starts the pod's infra container, so the
namespace exists before any workload process does: the sidecar starts,
the rules go in, then the workload starts. The listeners are on the
pod's loopback, and the redirect lands there.

Sharing the workload's namespace raises three problems the other
placements do not have:

1. **The programs' own dials.** The inspector's and the broker's
   upstream connections leave through the same namespace as the
   workload's, so the rules must tell them apart, or the inspector
   redirects itself. The programs run as uids of their own in the pod,
   and the rules key on `meta skuid`, which requires the workload's
   container to hold no `CAP_SETUID`, or workload root could become one
   of them. (`socket cgroupv2` also works and cannot be forged from
   inside; it is fiddlier.)
2. **Reaching the broker.** The inspector needs a way to the broker that
   the workload lacks. The broker runs in the same container as the
   inspector and listens on a filesystem socket in the sidecar's own
   tmpfs, `/run/customs/broker.sock`. The workload's container has no
   path to it — not by rule, by there being no such file in its mount
   namespace — and `SO_PEERCRED` stays the caller check. (A path
   socket, not an abstract one: abstract socket names live in the
   network namespace, which the workload shares.)
3. **The inspector's caller.** The workload is another uid by design,
   and the inspector serves only one it is told: `--caller-uid`, as the
   broker's flag is. Without it every connection is refused as foreign.

**Two uids in one container.** The broker runs as uid 201, owning the
key file `0400` and the socket `0660` under the shared group 200; the
inspector runs as uid 200. The inspector is the exposed surface: it
parses workload-controlled ClientHellos and HTTP/1 framing. The broker
holds the key, and the socket between them is the line. The responder
parses workload-controlled queries too and holds nothing, so it runs as
the inspector's uid. `setuid()` clears every capability, so no
`DAC_OVERRIDE` bridges the two uids whatever the container was started
with.

**The entrypoint.** The image is `container/Containerfile`, built from
the checkout root, and its entrypoint `container/customs-sidecar` is the
unit file as a process. As the container's root it binds the two
listeners and the responder's port on the pod's loopback; starts the
broker as 201 on `unix:/run/customs/broker.sock` with
`CREDENTIALS_DIRECTORY=/run/secrets`; mints the CA into the state volume
on the first start; then starts the inspector as 200 with its listeners
as fds 3 and 4 and `LISTEN_PID`/`LISTEN_FDS` set, and the responder as
200 with its own, answering every name with `127.0.0.1`. There is no
systemd in the image: the bind is still not the inspector's, and it is
root's before any privilege is dropped, which is what the socket unit
gives by another route. The entrypoint takes the two facts the image
cannot know — the workload's label and its uid — and passes every
other flag to the broker untouched.

**The recipe.**

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

The bundle the workload trusts is built from the CA the sidecar minted
(`podman exec sidecar cat /var/lib/customs/ca/egress-ca.crt`) over the
system store.

Both image uids are exempt from the redirect and the drop, since their
dials are the upstream legs. The drop chain cannot read the uid: `meta
skuid` needs the packet to carry the program's socket, and the segments
a connection sends after that socket is gone — the FIN and RST of a
program that exited, TIME_WAIT's ACKs — carry none. The `tag` chain
reads the uid at the output hook instead, stores it as a mark on the
connection, and copies that onto every packet of the connection, which
the egress hook can read. The mark needs no capability in the programs:
`SO_MARK` would need `CAP_NET_ADMIN`, which the sidecar does not hold.
A source address would need none either, but the workload shares the
namespace and could bind the same one. As written the exemption is
total, private addresses included; "Private addresses" above has the
lines that narrow it.

Pasta's forwarder is the programs' resolver, not the workload's: every
other port 53 is redirected to the responder, so the drop chain's
port-53 lines carry the programs' mark.

The pod has no cgroup of its own (`--share-parent=false`). With one,
every container's start asks systemd to create the pod's slice unless
podman finds its directory at the path it assumes for the user's
manager, and a slice systemd already has fails that start. Nothing here
sets a limit on the pod as a whole, so the slice would hold nothing the
pod needs.

**Capabilities.** The four the sidecar is given are the entrypoint's:
the chown of the two directories it hands over, the connect that sees
the broker listening on its `0660` socket, and the drops to 200 and 201.
The first-start mint runs as the inspector's uid, not as root: the
volume is the inspector's and outlives restarts, so root writing into it
would follow whatever the inspector left there. The entrypoint refuses a
`--caller-uid` of 0, 200 or 201, the uids the rules exempt, and starts
every program with a minimal environment rather than the container's.

**Supervision.** The entrypoint stays as the container's pid 1 and
supervises the three, which serve together or not at all. A stop is
forwarded to each program and the container exits 0. If any exits
unasked, the others are stopped and the container exits 1, so a broker
that dies takes the container with it and the restart policy, or a
quadlet's `Restart=`, brings them back. A restart reuses the volume's
CA, so the workload's bundle still holds. Until they are back, the
workload's redirected connections are refused: nothing listens, and the
rules stay in the pod's namespace. Once all have started the supervisor
holds no capability: its real uid is 200 and its effective and saved
uid 201, which lets it signal each and is not root. That is also why it
must be pid 1 and refuses `--init`: an init runs as root without
`CAP_KILL`, so it cannot signal a process with no uid 0, and a stop
would reach nobody.

The pod's `/proc/self/uid_map` is a rootless one, with the inside and
outside columns different. The inspector's and the broker's start-up
checks read the inside column, which is the uid the told `--caller-uid`
is in. The record's `upstream` for a brokered request reads
`unix:/run/customs/broker.sock`.

**What it buys and costs.** The programs become an image, not a host
install. On a host that already carries the RPM, the netns placement
gives the same isolation with fewer rules. The CA's private key lives
in the pod; a workload-container escape is a host escape, so this is
not a new exposure, but it is worth saying.

**Proved by** `tests/manual/sidecar_rig.py`, red without the rules. The
probe new to it: from the workload, the broker's socket path is ENOENT
— not ECONNREFUSED, which would mean the path exists and the mount is
shared — and nothing but the inspector's and the responder's ports
listens on TCP in the pod.

## VM: a VM inside a rootless container

**What runs where.** qemu is the workload: it runs inside the host
placement's container, with `--device /dev/kvm` and `-netdev passt` (or
`passt --socket` with `-netdev stream`). passt re-originates the
guest's traffic as sockets in the container's namespace, so the guest's
egress is the container's and the rules apply unchanged. Root in the
guest can rewrite the guest's own nft all day; the rules that matter
are one namespace out, where qemu and passt hold no `CAP_NET_ADMIN`.

The guest needs two things, both through its cloud-init seed: the
bundle and the variables that point at it, and the placeholder in the
agent's environment. SELinux in Enforcing needs no extra flag for
`--device /dev/kvm` or the bind mount. A shared directory wants
virtiofs or 9p.

The container contributes no isolation of its own, only the namespace
the rules hang on. Without it there is none to use: qemu with passt run
by the user on the host re-originates as the user, and the guest's own
namespace is the guest's. A VM on a bridge under system libvirt can be
filtered on the host by its tap, but that takes root.

**Proved by** `tests/manual/vm_rig.py`, which runs the host recipe with
qemu as the workload.

## With root: a uid per workload

With root, a workload can be given a system user of its own, and the
selector is its uid. The workload — a rootless podman container, or the
qemu of a VM — runs as that user, pasta or passt re-originates its
traffic as host sockets the uid owns, and rules in the host's own nft
select them with `meta skuid`. Nothing has to be loaded into a
namespace, and every workload's rules sit in one place, where the host's
root writes them.

workloadctl lays customs out this way. It creates a user per workload,
writes system units, and runs the inspector as the workload's user and
the broker under `DynamicUser=`, whose uid systemd draws from a range
disjoint from the workloads', so the credential is decrypted only where
that uid can read it. Its records of the decisions are its ADRs 007 to
009.

The programs are the same here as in every placement: the same flags,
policy, trust bundle and status files. customs ships no root layout;
workloadctl is one.

## What customs does not do

The programs allocate no uid, write no units, load no rules, install
nothing in the workload. They mint the CA
only when told to (`customs-mint-ca`, or the sidecar's first start).
Those are host management: they depend on how a host is laid out, and
whoever lays it out does them. `tests/test_closure.py` holds the
programs to importing nothing that knows what a workload is.

customs-box is one such layout, shipped in the same RPM: it writes a
box's units and loads its rules ([BOX.md](BOX.md)). It stands beside
the programs; they never import it.

## Proving a new placement

A new placement is proved on a real host, not by unit tests: one
container (or one VM in one), the programs placed as it says, the rules,
a placeholder in the workload's environment, and one real request that
reaches the provider carrying the sealed key. Then the negative probes:
the broker's socket path from inside (it must not exist — a refused
connect would mean the path is shared); an unlisted host (the inspector
must refuse it); the origin with no key (401). Expect a defect of the
"unit green, packet never arrives" kind. Each rig in
[tests/manual/](../tests/manual/) is one of these.
