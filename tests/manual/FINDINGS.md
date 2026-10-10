# What the rigs found

Each rig's runs on the proving host, dated: what each row and each break
flag showed, the defects a run found and how they were fixed, and the
facts about podman, pasta, systemd and the kernel that the design rests
on. How to run each rig, and what its rows and flags mean, is in
[README.md](README.md).

## host_rig.py — moatery with nothing but a normal user

**What it found, first run, 2026-09-22.** No defect in the pair. Four in
the host recipe as `DESIGN.md` had it, which is now corrected:

- podman starts pasta with `--no-map-gw`, so the gateway does not map to
  the host's loopback. The mapping is asked for with
  `--network pasta:--map-host-loopback=169.254.1.3`, a dedicated address.
- the container's resolver is pasta's forwarder (`169.254.1.1`), not the
  gateway; the DNS rule names that address.
- the policy's TLS mode is `"inspect"`, not `"terminate"`. The loader did
  not then validate the value, so the misspelling would have started a
  listener that refuses every terminated handshake for want of a minter.
  It refuses an unknown mode at start now.
- the inspector recognises exactly ports 8080 and 8443 as its planes, so
  "each container gets its own inspector port" is not something the
  program supports today: one inspected container per host loopback.

And two facts for the packaging step: the entrypoints find their modules
by `sys.path` only, so a checkout needs `PYTHONPATH` in the unit (an
install puts the package where Python looks); and nothing minted the CA, so the operator had
to, before the socket was first activated. `moat-mint-ca` is that
step now.

`SO_ORIGINAL_DST` on a host socket whose DNAT happened a namespace away
falls back to `getsockname()` cleanly: `caller_unresolved` is 0 and the
caller check admitted every connection as the user's.

**What it found, the responder, 2026-09-24.** 26/26;
`--without-dns-redirect` 10/25, with dns, request, neighbour, unlisted
and the inspector's counters red (the queries time out at the egress
drop, and nothing ever activates the inspector); `--without-rules` 8/25.
No defect in the responder. Three facts, two of them the rig's:

- podman seeds a container's `/etc/hosts` from the host's, and a name in
  it is never asked. The rig's own line for the provider sent curl to
  the container's loopback, where the DNAT to the map cannot route. The
  containers here and in the recipes are created with
  `--hosts-file image`.
- a socket-activated responder writes its first status when the first
  query starts it, after that query arrived and before it was counted.
  The DNS rows await a write from after their queries.
- pasta carries UDP over the loopback map in both directions, so the
  responder can sit on the host's `127.0.0.1` beside the inspector.

**What it found, HTTP/2, 2026-09-30.** 33/33; `--without-rules` 8/31
and `--without-dns-redirect` 11/31, the five `h2` rows red in both. No
defect in the pair. Two in the rows as first written:

- curl with `--http2-prior-knowledge` cannot read an HTTP/1.1 answer
  and exits 16 with no status, so the 400 is read from the record.
- the HTTPS query first asked for the provider's name, and without
  rules two rows stayed green: pasta's forwarder answers it nodata from
  the host's hosts file, and the previous run's responder line was
  still in the journal. It asks for a fresh name now.

**What it found, the first request, 2026-10-07.** The workload had been
`sleep infinity`, so its first packet was whichever probe the rig sent,
and rules loaded after `podman start` would have left every row green.
Its command is now the provider request, read back by the `first` row:
34/34; `--rules-after-start` 33/34, only `first` red (curl 7, the name
answered by pasta's forwarder from the hosts file); `--without-rules`
8/32, `first` among them, and `quic` and `h2` red too, which the flag's
list had left out.

## netns_rig.py — the listeners in the container's netns

**What it found, first run, 2026-09-24.** 21/21, and each flag red where
it should be: `--without-rules` 13/21, `--without-neighbour-discovery`
20/21 (the gateway `FAILED`, the query timed out),
`--without-netns-pid` 11/20 with the inspector's refusal in the journal.
No defect in the pair. Two facts for the design:

- joining the container's namespaces needs no podman. The user owns the
  container's user namespace, so a child holding a pidfd of the
  container's process can `setns` into its user and network namespaces
  together, and bind there.
- the caller check reads a different socket in this placement. On the
  host the inspector's peer is pasta's host socket, which is always the
  user's; here it is the workload's own, in the container's table, with
  the uid the host sees: the user for container root, a subuid for
  anything else.

**What it found, the responder, 2026-09-24.** 26/26;
`--without-dns-redirect` 14/26 (dns, request, unlisted); `--without-rules`
12/26. With the responder in the namespace nothing the workload may send
crosses the egress device, so the chain accepts nothing: the neighbour
row, which queried pasta's forwarder, went with the resolver's lines,
and `--without-neighbour-discovery` with it.

**What it found, the first request, 2026-10-07.** As host_rig's, and the
status waits moved after `podman start`, so the first request is queued
on the bound listeners while the programs load their policy: 31/31;
`--without-rules` 14/31, with `quic` and `another uid` added to its list;
`--rules-after-start` 29/31, `first` and `quic`. The quic red is the
fixture: the request before the rules left the gateway's neighbour entry
in DELAY, the chain then dropped its unicast probes, and by the quic row
it had FAILED, so the send waited on it and never reached the hook; a
40 s wait in a bare pasta container showed 443 and 9 both uncounted
under `quic`, only the ARP requests moving `dropped`. host_rig's chain
lets ARP out and its quic stayed green. The silent row's `dropped >= 1`
was green in the same run on those ARP drops alone: it shows the chain
dropped something, not that the port-9 send reached it.


**What it found, the neighbour, 2026-10-08.** The silent row now sends
`riglib.SILENT_SIZE` bytes and counts the chain's bytes, so ARP requests
(42 bytes each) cannot pass it. The rig pins pasta's gateway entry
PERMANENT before the rules load: in a bare pasta container under this
ruleset the entry was STALE at start, PROBE on first use and FAILED by
15 s, and from then a connect got EHOSTUNREACH without reaching the
chain, which passt hands a guest as a refusal. That is what a workload
in this placement sees: after its first quarter-minute a blocked
destination is refused at once, not timed out. 31/31;
`--rules-after-start` 30/31, only `first` (curl 7).

## sidecar_rig.py — moatery as a sidecar, with no host install

**What it found, first run, 2026-09-22.** One defect in the pair, the
seam kind: `peer_identity.userns_ranges` read the *outside* column of
`/proc/self/uid_map`. The uid the broker is told and the uids the kernel
reports to it are both inside values, and every layout the pair had run
under -- the initial namespace, `PrivateUsers=` -- had the two columns
equal, so the check passed everywhere it was tried and refused every uid
the first rootless broker had ("this user namespace cannot represent uid
200"). Fixed to the inside column; a unit test with a rootless map now
holds it, and the same check runs in the inspector under `--caller-uid`.

Two facts for the design, both now in `DESIGN.md`: nothing in the sidecar
needs `systemd-socket-activate` -- the entrypoint binds the planes as
root and hands them down as fds 3 and 4 with `LISTEN_PID`/`LISTEN_FDS`
set, then starts the inspector as its uid, which is the socket unit's
property (the bind is not the inspector's) by a different route;
and the entrypoint needs exactly `chown,dac_override,setgid,setuid` on
top of `--cap-drop all`, all of which `setuid()` clears before either
program runs. `SO_ORIGINAL_DST` answers in the pod rather than falling
back, since the DNAT is in the same netns: `caller_unresolved` is 0.

**What it found, the lifecycle rows, 2026-09-23.** Three defects in the
entrypoint, none of which the earlier rows could see because each run
started one fresh container and tore it down:

- a stop never arrived. `--init`'s catatonit runs as root without
  `CAP_KILL` and cannot signal uid 200, so every stop waited out the
  timeout and ended in SIGKILL (exit 137), and the inspector never wrote
  its last status. The entrypoint is pid 1 now and refuses `--init`.
- a second start on the same volume failed: the directory was already
  the inspector's, and the chmod that came first needs `CAP_FOWNER`.
- a dead broker left the inspector up and the container running, so no
  restart policy fired. The entrypoint supervises both now.

Seen red against the entrypoint before the fix: the three lifecycle rows
failed. The capability row was seen red against an image whose
supervisor skipped its drop (`CapEff=c3`), which also failed two
lifecycle rows: a root supervisor without `CAP_KILL` cannot stop the
inspector, so the uid arrangement is what makes the stop work.

**What it found, the private rows, 2026-09-24.** One defect in the
recipe as `DESIGN.md` had it: the private-space drop went before the
blanket accept, which came before the resolver's lines, so it dropped
the programs' own DNS to pasta's link-local resolver. The rig hid this
because `--add-host` pins every name the programs dial. Seen red with
the lines in that order (the DNS row, `timeout`); the resolver's lines
now come first, in the recipe and here. 29/29; `--without-private-drop`
27/29, the two drop rows red. The request the drop refuses is brokered,
so its record is the inspector's `forward` with the broker's 502, not
`internal destination`: that report is for the inspector's own dial.

**What it found, the responder, 2026-09-24.** 35/35;
`--without-dns-redirect` 27/35 (dns and unlisted; the resolver's accept
lines are the programs' now); `--without-rules` 15/35. In the first
version the provider's DNS row stayed green under `--without-rules`:
pasta's forwarder answered the name from the host's hosts file, with
the rig's own `127.0.0.1`, the address the responder gives in the pod.
The name is asked of a nameserver that does not exist now, which only
the redirect answers. `--without-rules` also turns neighbour and
private red, which its note had left out.


**What it found, the silent row, 2026-10-08.** It counts bytes, as
netns_rig's does: 38/38. The pod's chain drops ARP too and its entry is
not pinned; the counted sends come within seconds of the gateway's
first use.

## vm_rig.py — moatery under a VM

**What it found, first run, 2026-09-28.** 30/30; `--without-rules` 11/29,
`--without-dns-redirect` 15/29, `--without-neighbour-discovery` 13/29. No
defect in the pair. Four facts, all in the guest half:

- cloud-init's `scripts_user` caps a `runcmd` at about ten seconds and
  fails the module when it overruns, killing the command. A probe that
  can outlast that -- every red run -- has to be a systemd unit, not a
  `runcmd`.
- a systemd unit whose output goes to `/dev/ttyS0` stops at a write: the
  process ran (a busy loop advanced its clock) but the next write to the
  tty never returned, and the probe froze mid-row. The results go on a
  virtio-serial port (`-chardev file:...`) instead; the serial console
  stays for boot diagnostics.
- the guest's resolver is systemd-resolved's stub. The probe reads the
  uplink from `/run/systemd/resolve/resolv.conf` and queries it directly,
  and pins each HTTPS connection to the address the responder gave with
  the name in SNI, so neither depends on resolved's `.test` handling.
- qemu 10.2's `-netdev passt,id=net0` starts passt itself, in the
  container's netns, with no separate process and no shell entrypoint;
  the guest's DNS reaches pasta's forwarder through passt, where the
  port-53 DNAT claims it. SELinux in Enforcing needed no extra flag for
  `--device /dev/kvm` or the bind mount.


**What it found, boot, 2026-10-08.** The guest reports chronyd's
sources, stops it and waits five seconds; the rig takes its counter
baseline at that report, so egress and quic count the probe's sends
(by bytes) and not boot's. 32/32: chronyd's one source was the answered
169.254.1.3, reach 0, and the responder counted `2.fedora.pool.ntp.org`.
`--rules-after-boot` 30/32, only the two boot rows: four real pool
addresses reached, no name counted.

## vm_placement_rig.py — a VM in the netns and sidecar placements

**What it found, first runs, 2026-10-03.** One defect: the netns
placement, moathut and the sidecar answered every name with the
namespace's `127.0.0.1`, which a container dials into its own namespace
and a guest into its own stack, where passt never carries it. 14/20 in
both placements: DNS green, request, unlisted and drop red, the guest's
dials refused by its own loopback. Nothing left the namespace, and every
caller was named. With `198.18.0.1`, never routed, 20/20 in both; the
redirect is by port, and passt's dial to that address meets it. The
three now answer `198.18.0.1`, and `--loopback-answer` 14/20 is the old
answer as a control. Re-run on that change, the same day: vm_rig 30/30,
netns_rig 30/30, sidecar_rig 36/36, hut_rig 103/103.

Outside the rig, the same day, two more ways to hold a VM:

- qemu under pasta alone, with no podman (`pasta --config-net --
  qemu ...`), host_rig's listeners: 30/30 with vm_rig's rows, given two
  things podman supplies. pasta runs the command as root in its user
  namespace with every capability, so qemu was started under `setpriv
  --bounding-set=-all`; kept, the premise row goes red, and root there
  lists our tables. The namespace shares the host's mount namespace, so
  its `resolv.conf` names the host's `127.0.0.53`, which passt forwards
  to and no DNAT moves off loopback: DNS timed out until qemu had a
  mount namespace of its own and a `resolv.conf` naming pasta's
  forwarder.
- a krun microVM (`podman run --runtime krun`, crun-krun 1.28, libkrun
  1.19), in the host placement and in the netns: 11/11 and 6/6 of a
  smaller set (DNS, request with the real key, unlisted 403, drop,
  callers named), with either answer. krun hands the guest's sockets to
  its process in the container's namespace, loopback ones too. A dial to
  a dropped port fails in the guest at once (curl 7) instead of timing
  out; a listener on the host's end of it saw nothing.

**Every placement after the rename, 2026-10-04.** At 1d34a22, on the
proving host: host_rig 33/33, netns_rig 30/30, vm_rig 30/30, this rig
`--placement netns` 20/20 and `--placement sidecar` 22/22, sidecar_rig
38/38, hut_rig 130/130. No defect.


**What it found, boot and the neighbour, 2026-10-08.** vm_rig's boot
rows, egress by bytes since boot, netns_rig's ready rows, and
`--rules-after-boot`. The first netns run was 23/24: drop read errno
111, not a timeout. The guest's connect came after the five-second boot
wait, when the gateway's entry had FAILED (netns_rig.py's neighbour
paragraph); `--rules-after-boot` was 19/24, egress, quic and drop red
with boot. With the entry pinned: netns 24/24, sidecar 24/24, netns
`--rules-after-boot` 22/24, only boot (four real pool addresses, reach
1 to 3, no name counted).

## hut_rig.py — a moathut hut, through its command line

**What it found, first runs, 2026-09-29.** Three defects in moathut,
none of which the unit suite could see:

- `enter NAME --root -- COMMAND`, the documented form, handed `--root`
  to the command: the parser took everything after the name. Found
  writing the rig. The words after the first `--` are the command's now.
- a mount inside the home had its mount point, and every directory above
  it, made by the runtime as the hut's root: the user could not write in
  its own `~/.local`, and `rm --home`, which ignored errors, left the
  home and said nothing. `create` makes those directories as the user,
  and `rm --home` removes the home through `podman unshare`.
- the hut's user held all eleven of podman's default capabilities,
  effective and ambient, and could `chown` a root file without sudo. The
  home row above passed over a stale home the hut's root owned, which is
  how it showed. Podman gives a non-root user what `--cap-add` names,
  and a container whose user is not named gets root's set, which exec as
  the keep-id user keeps. The unit drops every capability outside the
  default set, adds none, and names the user.

53/56 at first (the home, and two rig rows matching the unlisted record
by path: the inspector refuses an unlisted host after the handshake,
before a request is read, so the record has none); then 57/57 with the
capabilities hidden; 57/58 with the added set gone and the user still
unnamed; 58/58. `--without-rules` 25/58. With `create`'s directories
left out the home row goes red, `Permission denied`.

Facts for the design. `podman pod restart` leaves every unit active
while the workload runs in a new namespace with no rules; its first
request there got no answer (no responder, and the provider's address
is the pod's own loopback), and `enter` refuses the hut, as
`docs/MOATHUT.md` says. `systemctl restart` of the pod returns in under a
second, before the listeners and the workload are back; quadlet adds
`Wants=` from the pod to its container, which is what brings the
workload back. A run takes under two minutes, `--without-rules` under
four.

**The broker, 2026-09-29.** 56/73 at first: the broker never started,
and every brokered request was refused 502 and recorded `credential
broker unreachable`, none sent without the key. systemd leaves a
credentialed unit's workspace,
`$XDG_RUNTIME_DIR/systemd/temporary-credentials/UNIT`, when it stops the
unit while its credentials are being decrypted, and every start after
fails `243/CREDENTIALS`, `File exists`, a restart after a restart, until
the user's manager ends. The fail rows' pod restarted, and the broker,
then `PartOf=` it and inside its 3 s, was stopped with it. Reproduced
with a bare unit: Type=notify, Type=simple with an `ExecStartPre=` or
`ExecStartPost=`, and Type=simple stopped in its first second, since
decrypting with `systemd-creds --user` takes over a second on the
proving host; a restart of an active unit is safe, and removing the
workspace from outside lets the next start through. The broker is bound
to nothing now; `stop` and `rm` stop it; `enter` and `credential add`
stop a broker that is not active, remove its workspace, forget its
failures, and start it. 63/75 while the repair skipped a broker waiting
to restart, which is `activating`; then 75/75. `--broker-not-ready`
68/75, the seven rows it names (an earlier 59/75, before the repair
covered every state but `active`, left the broker unable to start for
the rest of the run); `--without-rules` 36/75.

A broker's start is about 1.5 s on the proving host, the decryption and
the interpreter: as Type=simple, the first brokered request of every
start that starts it is refused. A run takes two minutes,
`--without-rules` four and a half.

**The policy loop, 2026-09-30.** 87/88 at first: the row for a killed
inspector wanted no new invocation at all, and the manager's start of
the inspector is one; re-derived to the inspector's alone. Then 88/88,
in 2m10s, and with the rows for a policy that drops the credential and
names it again, 91/91 in 2m17s. `--listeners-required` 85/88, the three
rows it names: with the workload requiring the listeners, `allow`
replaced the workload's container, so did the manager's automatic start
of the killed inspector, and stopping the inspector stopped the
workload. `--broker-not-ready` 83/91, the eight it names, the loop's
request after the broker is named again among them. `--without-rules`
41/88; its loop row for what `allow` restarts is red because an earlier
`enter`, refused, had left the broker stopped, and the inspector's
restart starts it (`Wants=`). A request while the inspector is stopped
gets curl's `000`, which is the listener's port refusing it: the rows
claim only that the workload runs on and is not served, not that
anything is blocked.

**The policy reload, 2026-09-30.** 97/97 in about 2m30s. The download,
5 MiB over 8 s through the inspector and the broker, had begun when
`allow` ran, was still running when it returned, and finished whole;
nothing restarted. `--without-reload` 92/97, the five it names: `allow`
waited out the reload, restarted the inspector, and said so ("since it
did not take the reload"), and the download ended at curl's `(56)
unexpected eof`, the cut the reload exists to avoid; the status file
row stays green, since the restarted inspector reads the new document
at its start. `--listeners-required` 94/97, the three it names; `allow`
no longer reaches the workload under it, since it restarts nothing.
`--without-rules` 46/97: every row that makes a request or reads one
back, and the killed inspector's, whose restart starts the broker an
earlier refused `enter` left stopped (`Wants=`); the reload's own rows,
the terminal's edit and Ctrl-C stay green, since none needs the rules.
`--broker-not-ready` 89/97, the eight it names; a first run gave 80/97:
the stop while the broker starts left its credential workspace behind,
its restarts hit the start limit on it, and it stayed down from
`enter` through the loop, where before `allow`'s restart of the
inspector had started it again (`Wants=`). The rerun is the one
recorded.

The rig had not reached the re-edit prompt or Ctrl-C before: every
command ran with its standard input on `/dev/null`, so `policy` never
saw a terminal and took the refusal's non-interactive path, and `log`
was ended with SIGTERM, not SIGINT.

`log --refused` on the run's own record, before `allow`:

```
refused, and refused by the policy now:
       2  unlisted.test  (not allowlisted)
       1  provider.test  (credential broker unreachable)
names asked for that no list admits:
       4  unlisted.test
       1  aaaa-b0d94ce6.exfil.test
```

**The record's rotation, 2026-09-30.** 100/100. The timer's own run of
the rotation had exited 0; the padded record, 33.5 MiB, moved to `.1`,
and the next request's line was in the new record, 402 bytes, and not
in the moved one. `--without-reopen` 99/100, the one row it
names: the line was in the moved record, and no new one was made,
since the inspector wrote on into the file it held open.
`--without-rules` 48/100: the rotation's row is red with the rows that
make a request, and the timer's two stay green, since neither needs the
rules.

**Autostart, 2026-09-30.** 103/103. quadlet adds the pod's unit to
the workload's `WantedBy=` itself, so the row reads `default.target`
among them. `--without-autostart` 99/103: create's `ls`, the two
autostart rows, and `outside`'s first, which restarts a pod that is
now not running. A real login is not driven: a lingering user's
manager outlives the ssh session, and `start default.target` is the
job the manager queues at its own start.

**No user site, 2026-10-03.** 103/103 against the RPM, with every
program's shebang and every interpreter line a hut's units carry
running `python3 -s`. The run before it was 102/103: `log` did not
end within 10 s of its SIGINT, once, and the rerun was green. `log`
starts with the rig's own interpreter, which the change does not
touch.

The same day, autostart was proven at a real boot, outside the rig: a
hut created with `--autostart`, linger on, the host rebooted. The
linger session (logind class `manager`) started the user's manager, and
the chain was active with its rules loaded before the first login
(class `user`).

**The held namespace, 2026-10-04.** The hut's namespace moved from its
pod to the netns unit (podman 5.8.7, systemd 259.9, crun 1.28,
kernel 7.2). 120/121 at first: the chain row read systemd's default
`Requires=app.slice basic.target` on the netns unit as a binding; it
asks now for none of the hut's units. Then 121/121. A shell `podman
exec --privileged` opens was refused `ip link add` and `ip link set lo
down`, and the host's nft as root with every capability in the hut's
user namespace was refused `nft flush ruleset` ("Operation not
permitted"), the tables staying; a left pod's `podman pod start` failed
with `crun: open .../moathut-netns/NAME: No such file or directory`.
`--without-held-netns` 112/121, the nine rows it names. `--without-rules`
63/121; warn's first stayed green there, since a refused enter opens no
shell to warn, and now asks that enter succeeded.

Facts for the design, from probes beside the rig the same day:
- with podman as the netns unit's main process, every stop left the
  unit failed: `podman unshare` exits 1 on SIGTERM (its shutdown
  handler);
- with MAINPID naming podman's child, a `kill -9` of that child left
  the unit active ("Supervising process ... which is not our child"):
  pasta kept the cgroup populated. The holder is a fork whose parent
  exits, so podman exits 0 and the holder's parent is the user manager;
  its `kill -9` then failed the unit, and the pod and pasta went with
  it, and the next `enter` served the hut again;
- moat-netns-listen's pidfd join of the infra's user and network
  namespaces at once works on a namespace the parent user namespace
  owns; joining the user namespace first, then the network one, is
  refused;
- a daemon-reload that gives a running unit `BindsTo=` on an inactive
  one stops it (two bare user units), which is why a running pod's
  network files wait for its next `enter`;
- a privileged exec keeps the hut's seccomp filter and `container_t`
  label: podman's exec changes capabilities alone, and crun applies the
  container's filter to every exec. The hut's user, without any
  capability, can already `unshare -Urn` and, inside, add links, open
  the netfilter socket and mount a tmpfs.

**The hut's seccomp profile, 2026-10-04.** On the proving host
(podman 5.8.7, crun 1.28, libseccomp 2.6.1, kernel 7.2.5): 126/126.
`--podman-seccomp` 124/126, the two rows of refusals, every call of
the probe reaching the kernel there (`clone3` EINVAL, `setns` EBADF,
`mount` ENOENT, `ptrace` ESRCH, `keyctl` ENOTSUP), a vsock refused EPERM
by podman's profile and one with an upper bit in its family made. The
unit tests' breaks (moathut's unit line, the file written with the
units, each of the profile's shapes) each turned a test red.

Beside the rig, in a container shaped like a hut (keep-id, the toolbox image)
under each profile: sudo, `dnf install`, git over HTTPS, curl and
threaded subprocesses worked under `strict` as under podman's default;
gdb ("During startup program exited with code 127"), strace and
`unshare -Ur` were refused, and under `debug` gdb and strace worked.
libseccomp's readings, measured the same day, are in
`tests/test_seccomp.py`'s docstring.

**A hut's SELinux level, 2026-10-04.** On the proving host (podman
5.8.7, SELinux enforcing): 130/130. Beside the rig, by hand: a
container at a level of its own in a pod at podman's random one ran at
its own level and wrote its `:Z` mount, and was refused `/dev/shm`,
which is the infra container's, labelled at the infra's level; with
the pod at the same level, `/dev/shm` was writable. A second start at
a fixed level left a file deep in a `:Z` mount with its ctime
unchanged: podman relabelled nothing. A container at another fixed
level, and one at podman's random one, were refused the directory.
The unit tests' breaks (the pod's level, the workload's, a level
different from the pod's, each of the four `:Z` mounts, a mount made
`:Z`, create's level, the level given a hut without one, a level drawn
twice, categories unsorted) each turned a test red.

**The sidecar's SELinux level, 2026-10-04.** On the proving host
(podman 5.8.7, SELinux enforcing), by hand, the recipe as it was: the
infra container, the sidecar and the workload ran at one level, the
pod's (`container_t:s0:c280,c478`); the policy and the secret were
labelled at it, and the named volume, mounted without `:Z`, at `s0`,
so a container mounting it without relabelling, as the inspector's
uid, read the CA key at the workload's level and at an unrelated one.
With the sidecar at a level of its own and the volume `:Z`, the three
were labelled at the sidecar's level, a container at the workload's
level or at podman's random one was refused the key, the workload's
loopback TCP to the sidecar was served, and the sidecar was refused
`/dev/shm`, the infra container's. Then `sidecar_rig.py` 38/38 and
`vm_placement_rig.py --placement sidecar` 22/22, the label rows among
them. `--shared-label`, the recipe as it was, turned both label rows
red and no other (36/38).

**The workspace, 2026-09-30: the user manager's alone.** A bare unit
loading a sealed credential, `ExecStart=sleep infinity`, started with
`--no-block` and stopped 0.05, 0.2, 0.4, 0.7 and 1.0 s into its 1.3 s
start, then started again, on systemd 259.9. As a system unit with
`DynamicUser=` (a credential sealed by `systemd-creds encrypt`), 5/5
left no workspace and started again; as a user unit, 5/5 left
`temporary-credentials/UNIT` and failed the next start. The system
manager decrypts into a tmpfs it mounts only once it is filled, and
falls back to the directory a killed start leaves only when it may not
mount one (`setup_credentials_plain_dir`, `src/core/exec-credential.c`,
the same on systemd's main branch). workloadctl's credentialed units,
all system units, are not exposed; `examples/systemd`'s broker is.

**The seccomp drift report, 2026-10-06.** On the proving host
(containers-common 0.67.2-1.fc44): 130/130. The report before the
seccomp rows read the host's `/usr/share/containers/seccomp.json` and
named nothing either way: the default allows nothing outright that
`strict` refuses beyond what it narrows, and `strict` allows nothing the
default does not beyond futex2's calls. Tried beside the rig against a
copy with a call added and one removed, it named both.

The first run was 129/130: `loop: Ctrl-C ends log` read `status None`,
`moathut log` still following ten seconds after the SIGINT. The rig had
been started as a shell's background job, which starts with SIGINT
ignored, and an ignored signal is inherited across exec, so neither the
rig nor the `log` it spawned had Python's handler (`signal.getsignal`
read 1 under that launch, `default_int_handler` in the foreground). The
rig now sets a SIGINT handler at its start, which every child gets back
as the default; the second run, launched the same way, read `status 0`.

**What it found, the window rows, 2026-10-08.** The silent row counts
bytes; recovery after a flush restarts the netns unit through `moathut
stop` and `enter` instead of the pod's; a new outside row holds the
first request after `podman pod restart` to have been inspected or
refused and never to have reached the provider. 132/132.

**A hut with no network policy, 2026-10-10.** 139/139. A hut made
`--network-policy none` had no table in its namespace, and its TCP
connect to a port on the host's address, through pasta's map, reached
the rig's listener; the rig's hut, beside it, timed out on the same
port and the listener read nothing from it. `--uninspected-ruled`
137/139, red on that hut's table and connect rows alone;
`--without-rules` 78/139, the rig's hut's connect reaching the listener
(`'sent'`) and the other uninspected rows green.
