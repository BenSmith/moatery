# Manual rigs

Checks that need a real host and cannot run under `just test`. Each is
invoked by hand, as an ordinary user, from a checkout on the proving host.
Nothing here is a unit gate; these are the gate the unit suites cannot be.
What each run found, dated, is in [FINDINGS.md](FINDINGS.md); a run worth
keeping is written up there.

The host and netns rigs run the checkout's programs, or with
`MOATERY_LIBEXEC=/usr/libexec/moatery` the installed RPM's, with no
`PYTHONPATH`; the premise line names which.

## Writing a row here

Every real defect the pair has had was correct code nothing connected to,
or a packet that never arrived, and the unit suite was green at every one.
A rig is what sees the seam, and a rig has blind spots of its own. The
rules below were each paid for by a defect that shipped past a green row.

**Probe the window, not the settled state.** A control that arms too
late — a filter, a policy load, a cgroup move — is indistinguishable from
a correct one by the time anything probes it. If a row sleeps before it
measures, ask what it would miss. Here the rules go into the netns
between `podman init` and `podman start`, and the row's request is the
container's first packet.

**Assert an observation, not the presence of a string.** Read what the
manager loaded, what the far side received, what the record wrote — not
the file that was meant to produce it. Where the property is "this must
not arrive", the observation is the receiver's log not growing, and the
control is a request that does arrive and does grow it.

**Pin the premise as its own row.** "The rules are in the netns" matters
only because the container cannot touch them; without a row for the
missing `CAP_NET_ADMIN`, the rules are a suggestion.

**A row can assert the defect and pass on it.** A row that pins a message
is green over a bug once the message becomes the wrong one. When the
product changes what it says, the row is re-derived from what it should
now say, never edited until it passes again.

**Check the fixture cannot satisfy the property by accident.** The rig's
own `/etc/hosts` line for the provider reached the containers, since
podman seeds a container's hosts file from the host's, and sent the
workload to its own loopback; and pasta's forwarder answered the same
name from the same line, with the address the responder gives in two
placements, so a DNS row passed with no responder at all. Where a row asserts
something is blocked, a control row proves an unblocked caller reaches
the same fixture, or a responder that never started satisfies every
assertion.

**Refused is not blocked.** Connection refused means the packet arrived
and nothing was listening, which is a broken fixture reporting itself as
a working filter. A drop presents as `EPERM` or a timeout.

**A run must be able to go red.** Every rig takes a flag that leaves out
the control it is about, and the rows that depend on it must fail under
that flag. A rig that has only ever passed has not been shown to measure.

`riglib.py` is the fixture the rigs share: the provider and unlisted
names, which nothing on the internet resolves, the stub, the CA and
bundle, the policy, the two sudo facts and their teardown, and the rows
every placement has (the workload's DNS, the origin's 401 and 200). A
rig owns its placement and its rows.

## host_rig.py — moatery with nothing but a normal user

`docs/DESIGN.md`, "Host": one rootless podman container under pasta,
the programs as hand-written user units, the nft rules loaded into the
container's netns through `podman unshare nsenter`, a placeholder in the
container's environment, and one real request that reaches the provider
carrying the sealed key.

```bash
python3 tests/manual/host_rig.py                  # every row green
python3 tests/manual/host_rig.py --without-rules  # must go red
python3 tests/manual/host_rig.py --without-dns-redirect  # dns red
python3 tests/manual/host_rig.py --broker-over-tcp  # the broker rows red
```

Runs as the user. Two host facts need `sudo`, and both are undone at
teardown: a line in `/etc/hosts` pointing `provider.test` at the stub,
and `net.ipv4.ip_unprivileged_port_start` lowered so the stub can bind
`:443` — both programs dial their upstream at 443 with no override, on
purpose, so the provider has to answer there. The stub
(`stub_provider.py`) returns 200 only to the real key and reports in the
body which `Authorization` arrived, so "200" means the substitution
happened and the placeholder alone measurably gets 401.

The per-workload CA is minted once into `~/.local/state/moatery-rig/` and
kept, like an SSH host key; everything else is rebuilt per run. `--keep`
leaves the container for inspection.

**Rows.** Premise (no `CAP_NET_ADMIN`; the table is in the netns). DNS:
the workload's queries for names nothing resolves, to its resolver over
UDP and TCP and to a nameserver that does not exist, are answered with
the loopback map; an AAAA gets no records; the provider's name is
answered the same; the responder's status names the unlisted names and
not the provider's. The container has no `--add-host`, so the request
and unlisted rows resolve through the responder too. A filtered UDP
send returns without error while the drop counter moves, and one to
443 moves the `quic` counter too. HTTP/2: curl offering h2 gets 200
over HTTP/1.1; HTTP/2's preface on the cleartext plane is recorded as
refused with 400 and noted once; an HTTPS query gets no records, a
responder line and a count under `https`. The request (200;
the real key arrived; the container's environment holds
the placeholder only; the broker's journal grew by one; the record says
`forward` under the credential). The broker's address is unreachable
from inside both ways it can be spelled, and its journal did not grow.
An unlisted host gets the inspector's own 403 and a record saying
`not allowlisted` with no upstream. The origin gives the placeholder 401
and the real key 200. The counters name every caller and dropped none as
foreign.

## netns_rig.py — the listeners in the container's netns

`docs/DESIGN.md`, "Netns": host_rig's container under plain pasta, with
no loopback map, and host_rig's broker unit. The inspector and the responder
are transient user units started between `podman init` and `podman
start`, through `moat-netns-listen`, which binds their sockets in the
container's network namespace and execs each program with its own.

```bash
python3 tests/manual/netns_rig.py                        # every row green
python3 tests/manual/netns_rig.py --without-rules        # must go red
python3 tests/manual/netns_rig.py --without-netns-pid    # inspector red
python3 tests/manual/netns_rig.py --without-dns-redirect # dns red
python3 tests/manual/netns_rig.py --without-notify       # ready red
```

**Rows.** host_rig's premise, DNS, silent-drop, quic, request, broker,
unlisted, origin and counter rows, and four of its own. The inspector is
up on the listeners it was handed, and their inodes are rows in the
container's socket table and in none of the host's. Nothing listens on
the host's `127.0.0.1` at either plane, for the user or another uid;
the request row, which reaches the same planes from inside, is the
control. The request's 200 is also the observation that the inspector's
upstream dial left from the host's namespace: the stub is on the host's
`127.0.0.1`, which the container cannot reach. A request from another
uid inside the container (65534, a subuid outside) is served too: the
inspector serves every uid of the container's user namespace, which is
what sudo inside needs.

The listener units are `Type=notify`: when `systemd-run` returned, each
unit's ports were already listening in the container's namespace.
`--without-notify` starts them as `Type=simple`, and on the proving host
neither had bound anything by then.

`--without-netns-pid` starts the inspector without the flag. It must
refuse to start, since its lookups would read the host's table, which
the listeners are not in, so inspector, request, unlisted and counters
go red.

## sidecar_rig.py — moatery as a sidecar, with no host install

`docs/DESIGN.md`, "Sidecar": a podman pod under pasta, the sidecar image
(`container/`: the programs, one container, two uids) beside a workload
container running as a third uid with no capabilities, the nft rules in
the pod's netns keyed on `meta skuid`, the broker on a socket path under
the sidecar's own `/run`, the key as a podman secret, and one real request
that reaches the provider carrying it.

```bash
python3 tests/manual/sidecar_rig.py                  # builds the image first
python3 tests/manual/sidecar_rig.py --without-rules  # must go red
python3 tests/manual/sidecar_rig.py --without-private-drop  # private red
python3 tests/manual/sidecar_rig.py --without-dns-redirect  # dns red
python3 tests/manual/sidecar_rig.py --no-build       # reuse the last image
```

The image is built from the checkout on each run; the state volume and
the secret are removed at teardown, so the CA is the sidecar's and is
minted afresh each run. `--keep` leaves the pod, the volume and the
secret.

**Rows.** Premise (the workload holds neither `CAP_NET_ADMIN` nor
`CAP_SETUID`; the table is in the pod's netns; `podman top` shows the
broker and the inspector as the two image users and the responder as the
inspector's, and the supervising pid 1 holds no capability). host_rig's
DNS rows, answered by the sidecar's responder with the pod's loopback;
the unlisted row resolves through it too, while the provider's name is
in the pod's hosts file, which the sidecar's dials need. host_rig's
silent-drop and quic rows. The request (200; the real key arrived; the
workload's environment holds the placeholder only; the broker's log grew
by one; the record says `forward` under the credential with `upstream`
naming the socket path). The broker's path is ENOENT from the workload
-- `stat` says "No such file or directory", which curl alone cannot
distinguish from a refusal -- and nothing but the two planes and the
responder's port listens on TCP in the pod, so there is no address to
spell; its log did not grow. An unlisted host gets the 403 and the
record. The private rows: the egress chain carries `DESIGN.md`'s
private-space drop and an accept line for the provider, which is on the
host's mapped loopback and so link-local; with that line deleted the
workload's request gets no 200, the stub's log does not grow and the
drop's counter moves, and with it put back the same request arrives. The
programs' own DNS query to the resolver is answered. The origin's two
rows. The counters name every caller and dropped none as foreign, with
the workload being another uid. Last, the lifecycle: the broker killed
from outside ends the container non-zero and the restart policy brings
it back (the restart count rose; every exit is in the log), the
restarted programs serve the workload's request under the CA its bundle
already holds, and a stop reaches every program well inside podman's
timeout and exits 0.

## vm_rig.py — moatery under a VM

`docs/DESIGN.md`, "VM": one rootless podman container under pasta whose
only payload is qemu and the passt backend qemu starts itself, the
guest's egress re-originated by passt as sockets in the container's
netns, moatery as host_rig's hand-written user units on the host, the
nft rules loaded into the container's netns, and a workload inside the
guest that reaches the provider carrying the sealed key.

```bash
python3 tests/manual/vm_rig.py                  # builds the qemu image first
python3 tests/manual/vm_rig.py --without-rules  # must go red
python3 tests/manual/vm_rig.py --without-dns-redirect  # dns red
python3 tests/manual/vm_rig.py --without-neighbour-discovery  # dns red
python3 tests/manual/vm_rig.py --no-build       # reuse the last image
python3 tests/manual/vm_rig.py --keep           # leave the container
```

Runs as the user, on a KVM host with `/dev/kvm` readable and writable.
The operator puts a Fedora Cloud Base Generic qcow2 at
`~/.local/state/moatery-rig/vm/guest.qcow2` once (44-1.7 was used);
the rig builds its own qemu image from `vm.Containerfile`. The guest
probe (`vm_guest.py`) goes in through the NoCloud seed with the CA
bundle and the agent's environment, and reports on a virtio-serial port
the host reads as a file.

**Rows.** Premise (no `CAP_NET_ADMIN` in the container; the table is in
its netns; qemu holds `/dev/kvm`; the guest is a namespace inside the
container's; the guest's own nft tables hold none of ours; the neighbour
table is flushed before the guest's first packet). The guest's UDP sends
return while the container chain's `dropped` counter moves -- the guest's
egress IS the container's. host_rig's DNS rows, asked from inside the
guest. The silent-drop and quic rows. The request (200; the real key
arrived; the response names the provider's server; the guest's
environment holds the placeholder only; the broker's journal grew by one;
the record says `forward` under the credential). The broker's rows, plus
a guest connect to a map port nothing accepts (timeout, drop counter).
The unlisted row. The origin's two rows. The counters.

## vm_placement_rig.py — a VM in the netns and sidecar placements

vm_rig.py's qemu container and guest, moved into the two placements whose
listeners are in the workload's namespace: netns_rig's host side (the
broker a user unit, the listeners bound in the qemu container's namespace
by moat-netns-listen), or sidecar_rig's pod with the qemu container as
its workload, uid 1000 with every capability dropped.

```bash
python3 tests/manual/vm_placement_rig.py --placement netns
python3 tests/manual/vm_placement_rig.py --placement sidecar  # builds
python3 tests/manual/vm_placement_rig.py --placement netns \
    --loopback-answer                                       # must go red
python3 tests/manual/vm_placement_rig.py --placement netns --no-build
```

It needs what vm_rig needs. The guest reads the address the responder
answers with from the seed (`/etc/moatery-rig/answer`) and dials whatever
it is given, so a wrong answer is a failed request and not a skipped one.
The sidecar's qemu runs as a subordinate uid, so the serial and probe
files are made first, writable by anyone, and its `/proc` is read through
`podman unshare`.

**Rows.** Premise (no `CAP_NET_ADMIN` in qemu's bounding set; the table is
in the namespace; qemu holds `/dev/kvm`; the guest is a namespace of its
own). DNS from the guest, answered with riglib.ANSWER. The guest's UDP
sends dropped and the one to 443 counted as quic. The request (200; the
real key arrived; the record says `forward` under the credential; the
guest holds the placeholder only). The unlisted row. A guest connect to
another port at the answered address times out. The counters.

## hut_rig.py — a moathut hut, through its command line

`docs/MOATHUT.md`: `moathut credential add`, `create`, `enter`, `log`,
`allow`, `policy`, `stop` and `rm`, the hut's units run by the user's
manager and quadlet, the namespace its netns unit holds, the netns
placement's rules and listeners in it, and the hut's broker.
The tool is the checkout's `bin/moathut`, or with
`MOATERY_LIBEXEC=/usr/libexec/moatery` the installed one.

```bash
python3 tests/manual/hut_rig.py                     # every row green
python3 tests/manual/hut_rig.py --without-rules     # must go red
python3 tests/manual/hut_rig.py --without-held-netns  # must go red
python3 tests/manual/hut_rig.py --podman-seccomp    # must go red
python3 tests/manual/hut_rig.py --broker-not-ready  # must go red
python3 tests/manual/hut_rig.py --listeners-required  # must go red
python3 tests/manual/hut_rig.py --without-reload    # must go red
python3 tests/manual/hut_rig.py --without-reopen    # must go red
python3 tests/manual/hut_rig.py --without-autostart  # must go red
python3 tests/manual/hut_rig.py --restarts 10       # more restarts of each
```

The fixture is riglib's, and seven drop-ins beside the units `create`
writes, removed before `rm`: the inspector and the broker trust the
stub's certificate, and under `--without-reload` the inspector's unit
has no `ExecReload=`; the broker's interpreter sleeps 3 s before it runs,
so its start has a window, and under `--broker-not-ready` its unit is
Type=simple; the namespace's unit finds an nft that fails ahead of the
system's, for two rows, or one that loads nothing, under
`--without-rules`; the pod's unit keeps the pod at its stop, for one
row; under `--without-held-netns` the pod makes its own namespace, and
loads the rules into it at its start; and the workload's `Exec=` is a
script whose
first act at every start is a request to the provider, with a nonce in
its path, recorded in the hut's home, and under `--listeners-required`
its unit `Requires=` both listeners, as it did before the policy loop;
and under `--without-reopen`, for the record's row alone, the
rotation's `ExecStart=` is an `mv` of the record and signals nothing.
That request is the window: the row for each start is the stub's log and
the record naming its nonce.
The provider is brokered: the rig seals a key with `credential add`, the
hut holds a placeholder, and the stub answers 200 only to the sealed
key, which only the broker has, and 401 to anything else. Its
`/slow/N/` path, with the key, is a download of N 64 KiB chunks 0.1 s
apart, long enough for an `allow` to land in it.

**Rows.** `credential add` seals the key, and neither file holds it. The
files `create` lays out, and nothing started; the hut is made with
`--autostart`, and `ls` says so. The chain as the manager
loaded it: the workload wants the listeners and requires neither, the
broker is Type=notify and bound to nothing, the pod is bound to the
namespace's unit, which is Type=notify and bound to nothing of the
hut's, and the pod pulls in the record's rotation timer, which is
`PartOf=` it. A failing rules
load starts nothing: `enter` refuses, the workload's first act never
happened, and `stop` leaves nothing active. The first request, brokered,
at the first start, at every workload restart and pod restart, and
after `stop` and `enter`. Root in the hut holds no `CAP_NET_ADMIN` and
the user no capability; the rules are in the pod's namespace, which is
the one the netns unit holds; the pod has no cgroup. Root in a shell
`podman exec --privileged` opens is refused `ip link add` and `ip link
set lo down`, and the host's nft with those credentials is refused
`nft flush ruleset`, the rules staying; that shell does not warn; the
hut's pasta has the arguments podman gives a stock pod's. Each pod
restart keeps the held namespace. `enter`'s user, home, working directory and `--root`.
The hut's home is not the user's, and the directories between it and a
mount in it are the user's. A `:ro` mount. The host's hosts file is not
the hut's. riglib's DNS rows, the silent drop, quic, and TCP 22 dropped.
The brokered host and the unlisted one, as the user and as root by sudo.
The hut's placeholder, by exec and by `enter`, and never the key; the
broker's socket on the host and not in the hut, and no TCP socket. A
stopped broker: a request is refused 502, never reaches the provider,
and the record says `credential broker unreachable`; `enter` starts it
again. The premise that systemd will not start a broker stopped while
it starts, and `enter` starting it anyway. `credential add` with a new
key, which the stub now wants: the next request carries it, and the
broker restarted while the inspector and the workload did not. The
inspector's counters. The policy loop: `log --refused` counts the
unlisted host's 403s and names it among the responder's unlisted names;
`allow` lists it and reloads the listeners, restarting nothing, and the
inspector's status file names the new document; the host is then
dialled and not refused, and `log --refused` stops listing it; a
download through the inspector, begun before an `allow` and still
running when it returns, finishes whole, every byte in order; a
`policy` edit the loader refuses exits 1 and restarts nothing, and at a
terminal (a pty) asks, opens the editor again, and applies the second
document, reloading the listeners; one dropping the credential stops
the broker and removes its unit, and the provider is reached unbrokered
(the stub's 401), and one naming it again brings the broker back and
the provider is served; the inspector killed is started again, and
nothing else is; stopped, the workload runs on in its container, and
`enter` starts it again; `log` follows a request just made, and SIGINT,
which is Ctrl-C, ends it with status 0 and no traceback. The record's
rotation: its timer active with the pod and its run exited 0; the
record padded past 32 MiB, the manager's run of the rotation moves it
aside, and the next request's line is in a new record and not in the
moved one. A file outside
the home is gone after a restart. Autostart: the manager loaded the
workload as wanted by `default.target`, and with the hut stopped, its
start of `default.target`, which is what a login or a lingering boot
does, starts the hut with the rules, and the first request is
inspected; a hut made without `--autostart` it does not start. After
`podman pod restart` the pod is in the held namespace, with the rules,
and `enter` serves it; with a table deleted from the host, `ls` marks
the hut unprotected and `enter` refuses it, and `stop` then `enter`
serves it again; a container run by hand from the hut's image, prompt
and mark warns; a pod the hut left does not start while the namespace's
unit is stopped. `credential
rm` is refused while the hut names the credential. `rm` leaves no unit,
pod or container, nor the broker's socket, and keeps the home and the
record; `create`, with a policy naming no credential, finds the home
again and writes no broker; `rm --home` removes it; then `credential rm`
removes the credential.
